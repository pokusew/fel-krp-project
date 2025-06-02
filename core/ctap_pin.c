#include "ctap.h"
#include "utils.h"

/**
 * Counts the number of Unicode code points in the given UTF-8 string
 *
 * The given string is assumed to be a valid UTF-8 sequence of bytes.
 * No validation is performed by this function.
 * If the given string is NOT a valid UTF-8, the returned value might be incorrect.
 *
 * @param str a UTF-8 string (without the terminating null byte)
 * @param str_length the string length (without the terminating null byte)
 * @return the number of Unicode code points in the given UTF-8 string \n
 *         If the given string is NOT a valid UTF-8, the returned value might be incorrect.
 */
static size_t count_unicode_code_points_in_utf8_string(const uint8_t *str, const size_t str_length) {

	// In UTF-8, a single Unicode code point might be encoded in one to four bytes,
	// see https://en.wikipedia.org/wiki/UTF-8#Description.

	// Note that TinyCBOR contains UTF-8 validation function validate_utf8_string
	// in tinycbor/src/cborvalidation.c (uses tinycbor/src/utf8_p.h).
	// However, it would be better to count Unicode code points while performing the validation
	// (to avoid additional unnecessary looping over the string).

	// credits: https://stackoverflow.com/a/3586973
	// This code works only for a valid UTF-8 sequence of bytes.
	size_t count = 0;
	for (size_t i = 0; i < str_length; ++i) {
		// if NOT a continuation byte
		// see https://en.wikipedia.org/wiki/UTF-8#Description
		if ((str[i] & 0xC0u) != 0x80u) {
			++count;
		}
	}

	return count;

}

static void update_persistent_pin_state(ctap_state_t *state) {
	const ctap_storage_t *const storage = state->storage;
	ctap_storage_item_t item = {
		.handle = state->pin_state_item_handle,
		.key = CTAP_STORAGE_KEY_PIN_INFO,
		.size = sizeof(state->pin_state),
		.data = (const uint8_t *) &state->pin_state,
	};
	if (storage->create_or_update_item(storage, &item) == CTAP_STORAGE_OK) {
		debug_log("created or updated pin_state in the storage" nl);
		state->pin_state_item_handle = item.handle;
	} else {
		error_log(red("creating or updating pin_state in the storage failed") nl);
		// TODO: propagate error
	}
}

static void decrement_pin_remaining_attempts(ctap_state_t *state) {

	assert(state->pin_boot_remaining_attempts > 0);
	state->pin_boot_remaining_attempts--;

	assert(ctap_get_pin_total_remaining_attempts(state) > 0);
	state->pin_state.pin_total_remaining_attempts--;
	update_persistent_pin_state(state);

}

static void reset_pin_remaining_attempts(ctap_state_t *state, bool perform_persistent_update) {

	state->pin_boot_remaining_attempts = CTAP_PIN_PER_BOOT_ATTEMPTS;

	if (ctap_get_pin_total_remaining_attempts(state) < CTAP_PIN_TOTAL_ATTEMPTS) {
		state->pin_state.pin_total_remaining_attempts = CTAP_PIN_TOTAL_ATTEMPTS;
		if (perform_persistent_update) {
			update_persistent_pin_state(state);
		}
	}

}

static uint8_t check_pin_remaining_attempts(ctap_state_t *state) {
	if (ctap_get_pin_total_remaining_attempts(state) == 0) {
		return CTAP2_ERR_PIN_BLOCKED;
	}
	if (state->pin_boot_remaining_attempts == 0) {
		return CTAP2_ERR_PIN_AUTH_BLOCKED;
	}
	return CTAP2_OK;
}

static uint8_t handle_invalid_pin(ctap_state_t *state, ctap_pin_protocol_t *pin_protocol) {
	uint8_t ret;
	decrement_pin_remaining_attempts(state);
	pin_protocol->regenerate(pin_protocol);
	ctap_check(check_pin_remaining_attempts(state));
	return CTAP2_ERR_PIN_INVALID;
}

static uint8_t check_pin_hash(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const ctap_string_t *const pin_hash_enc,
	const uint8_t *const shared_secret
) {
	// These preconditions should be ensured by the caller function.
	assert(ctap_get_pin_total_remaining_attempts(state) > 0);
	assert(state->pin_boot_remaining_attempts > 0);

	// Note: This case is not explicitly mentioned in the spec.
	if (!ctap_is_pin_set(state)) {
		return CTAP2_ERR_PIN_NOT_SET;
	}

	// The spec suggests, that we should decrement the pinRetries counter.
	// by 1 BEFORE actually checking the pin. Then, if the pin is correct,
	// we should reset the pinRetries counter to the maximum value.
	// To avoid the unnecessary decrement/reset, we decrement the pinRetries counter
	// ONLY IF that pin is actually incorrect (in handle_invalid_pin).

	// Authenticator decrypts pinHashEnc using decrypt(shared secret, pinHashEnc)
	// and verifies against its internal stored LEFT(SHA-256(curPin), 16).
	const size_t expected_pin_hash_length = sizeof(state->pin_state.pin_hash);
	if (pin_hash_enc->size < pin_protocol->encryption_extra_length) {
		return handle_invalid_pin(state, pin_protocol);
	}
	const size_t pin_hash_length = pin_hash_enc->size - pin_protocol->encryption_extra_length;
	if (pin_hash_length != expected_pin_hash_length) {
		return handle_invalid_pin(state, pin_protocol);
	}
	uint8_t pin_hash[pin_hash_length];
	if (pin_protocol->decrypt(
		pin_protocol,
		/* key */ shared_secret,
		/* ciphertext */ pin_hash_enc->data, pin_hash_enc->size,
		/* output: plaintext */ pin_hash
	) != 0) {
		return handle_invalid_pin(state, pin_protocol);
	}
	if (memcmp(state->pin_state.pin_hash, pin_hash, sizeof(state->pin_state.pin_hash)) != 0) {
		return handle_invalid_pin(state, pin_protocol);
	}

	// 5.8 Authenticator sets the pinRetries counter to maximum value.
	reset_pin_remaining_attempts(state, true);

	return CTAP2_OK;
}

/**
 * Sets a new PIN
 *
 * 1. Decrypts newPinEnc to produce paddedNewPin
 * 2. Drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
 * 3. Validates newPin length.
 * 4. Persists newPin.
 *    (newPin length aka PINCodePointLength and LEFT(SHA-256(newPin), 16) aka CurrentStoredPIN).
 * 5. Resets the pin remaining attempts counters to their resp. max values.
 *
 * @returns CTAP2_OK pin successfully set and persisted
 *          CTAP1_ERR_INVALID_PARAMETER invalid paddedNewPin, resp. newPinEnc
 *          CTAP2_ERR_PIN_AUTH_INVALID when newPinEnc decryption fails (should not happen)
 *          CTAP2_ERR_PIN_POLICY_VIOLATION newPin too short
 */
static uint8_t set_pin(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const ctap_string_t *const new_pin_enc,
	const uint8_t *const shared_secret
) {

	// 6.5.5.5. Setting a New PIN:     5.7
	// 6.5.5.6. Changing existing PIN: 5.10
	//   If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER
	if (new_pin_enc->size < pin_protocol->encryption_extra_length) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}
	const size_t padded_new_pin_length = new_pin_enc->size - pin_protocol->encryption_extra_length;
	if (padded_new_pin_length != 64) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 6.5.5.5. Setting a New PIN:     5.6
	// 6.5.5.6. Changing existing PIN: 5.9
	//   The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
	//   If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	uint8_t padded_new_pin[64];
	if (pin_protocol->decrypt(
		pin_protocol,
		/* key */ shared_secret,
		/* ciphertext */ new_pin_enc->data, new_pin_enc->size,
		/* output: plaintext */ padded_new_pin
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// 6.5.5.5. Setting a New PIN:     5.8
	// 6.5.5.6. Changing existing PIN: 5.11
	//   The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
	uint8_t *new_pin = padded_new_pin;
	// iterate from the end (i.e., from the right) and stop on the first non-zero byte
	size_t new_pin_length = 64;
	while (new_pin_length > 0) {
		if (padded_new_pin[new_pin_length - 1] != 0x00) {
			break;
		}
		new_pin_length--;
	}
	// Authenticators MUST enforce "Maximum PIN Length: 63 bytes"
	// Note:
	//   This case, i.e., when the new_pin_length > 63 (at this point in the code, it implies new_pin_length == 64)
	//   after the step "The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin."
	//   is not explicitly mentioned in the spec.
	//   However, the FIDO Conformance Tools v1.7.22: CTAP2.1 - MDS3
	//   expects the authenticator to return CTAP2_ERR_PIN_POLICY_VIOLATION
	//   (Authr-ClientPin1-Policy Check, F-2).
	if (new_pin_length > 63) {
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	}

	// 6.5.5.5. Setting a New PIN:     5.9
	// 6.5.5.6. Changing existing PIN: 5.12
	//   The authenticator checks the length of newPin against the current minimum PIN length,
	//   returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
	//
	//   An authenticator MAY impose arbitrary, additional constraints on PINs.
	//   If newPin fails to satisfy such additional constraints,
	//   the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
	//
	// 6.5.1. PIN Composition Requirements states that
	//   Platforms MUST enforce the following, baseline, requirements on PINs used with this specification:
	//     * Minimum PIN Length: 4 Unicode characters
	//     * Maximum PIN Length: UTF-8 representation MUST NOT exceed 63 bytes
	//     * PIN are in Unicode normalization form C.
	//     * PIN MUST NOT end in a 0x00 byte
	//   Authenticators MUST enforce the following, baseline, requirements on PINs:
	//     * Minimum PIN Length: 4 Unicode code points.
	//         Note: Authenticators can enforce a greater minimum length.
	//     * Maximum PIN Length: 63 bytes
	//     * PIN storage on the device has to provide the same, or better, security assurances
	//       as provided for private keys.
	//
	// Note the difference between a Unicode characters and a Unicode code point:
	// (from 6.5.5.5. Setting a New PIN):
	//   An arbitrary Unicode character corresponds to one or more Unicode code points.
	//   While the platform (client) enforces a user-visible limit of at least four Unicode characters
	//   for the PIN length (e.g., by counting grapheme clusters), this results in actually collecting
	//   at the very minimum four Unicode code points, and perhaps (many) more,
	//   depending on the script employed.
	//
	// From the requirements above, it is clear that a CTAP-compliant platform (client) will always
	// send a PIN that has at least 4 Unicode characters (which implies at least 4 Unicode code points).
	// However, to comply with the standard, we (as the authenticator) must verify and enforce
	// that the PIN contains at least 4 Unicode code points.
	//
	// PIN is encoded in UTF-8.
	// TODO: Consider checking that it's really a valid UTF-8 sequence of bytes.
	// In UTF-8, a single Unicode code point might be encoded in one to four bytes.
	// For example, the RELIEVED FACE emoji is a a single Unicode code point U+1F60C,
	// which is encoded as 4 bytes (0xF0 0x9F 0x98 0x8C) in UTF-8.
	//
	// Therefore, a simple check such as `new_pin_length >= 4` would not be sufficient.
	// We need to count the number of Unicode code points in the new_pin
	// in order to comply with the CTAP2.1 standard, which states in 6.5.1. PIN Composition Requirements
	// that "Authenticators MUST enforce the minimum PIN Length of 4 Unicode code points".
	const size_t new_pin_code_point_length = count_unicode_code_points_in_utf8_string(new_pin, new_pin_length);
	const size_t pin_min_code_point_length = ctap_get_pin_min_code_point_length(state);
	if (new_pin_code_point_length < pin_min_code_point_length) {
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	}
	assert(new_pin_code_point_length <= 63);

	// 6.5.5.5. Setting a New PIN:     5.11, 5.12
	// 6.5.5.6. Changing existing PIN: 5.15, 5.17
	//   Authenticator remembers newPin length internally as PINCodePointLength.
	//   Authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
	//   sets the pinRetries counter to maximum count, and returns CTAP2_OK.

	debug_log(green("new_pin = %s") nl, new_pin);

	uint8_t new_pin_hash[CTAP_SHA256_HASH_SIZE];
	const ctap_crypto_t *const crypto = state->crypto;
	ctap_crypto_check(crypto->sha256_compute_digest(crypto, new_pin, new_pin_length, new_pin_hash));

	// CurrentStoredPIN = LEFT(SHA-256(newPin), 16)
	static_assert(
		CTAP_PIN_HASH_SIZE <= sizeof(new_pin_hash),
		"CTAP_PIN_HASH_SIZE must be less than or equal to 32 bytes (the size of the SHA-256 output)"
	);

	memcpy(state->pin_state.pin_hash, new_pin_hash, CTAP_PIN_HASH_SIZE);
	state->pin_state.pin_code_point_length = new_pin_code_point_length;
	state->pin_state.is_pin_set = 1u;
	reset_pin_remaining_attempts(state, false);
	update_persistent_pin_state(state);

	return CTAP2_OK;

}

uint8_t ctap_client_pin_set_pin(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const CTAP_clientPIN *const cp
) {

	// 6.5.5.5 Setting a New PIN

	// 5.1 If the authenticator does not receive mandatory parameters for this command,
	//     it returns CTAP2_ERR_MISSING_PARAMETER error.
	const uint32_t mandatory_params =
		ctap_param_to_mask(CTAP_clientPIN_keyAgreement) |
		ctap_param_to_mask(CTAP_clientPIN_pinUvAuthParam) |
		ctap_param_to_mask(CTAP_clientPIN_newPinEnc);
	if (!ctap_is_present(cp->present, mandatory_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// 5.3 If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
	if (ctap_is_pin_set(state)) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// 5.4 The authenticator calls decapsulate on the provided platform key-agreement key
	//     to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, &cp->keyAgreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 5.5 The authenticator calls verify(shared secret, newPinEnc, pinUvAuthParam)
	//     If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	uint8_t verify_ctx[pin_protocol->verify_get_context_size(pin_protocol)];
	pin_protocol->verify_init_with_shared_secret(pin_protocol, &verify_ctx, /* key */ shared_secret);
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* message */ cp->newPinEnc.data, cp->newPinEnc.size);
	if (pin_protocol->verify_final(pin_protocol, &verify_ctx, cp->pinUvAuthParam.data, cp->pinUvAuthParam.size) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	return set_pin(state, pin_protocol, &cp->newPinEnc, shared_secret);

}

uint8_t ctap_client_pin_change_pin(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const CTAP_clientPIN *const cp
) {

	uint8_t ret;

	// 6.5.5.6. Changing existing PIN

	// 5.1 If the authenticator does not receive mandatory parameters for this command,
	//     it returns CTAP2_ERR_MISSING_PARAMETER error.
	const uint32_t mandatory_params =
		ctap_param_to_mask(CTAP_clientPIN_keyAgreement) |
		ctap_param_to_mask(CTAP_clientPIN_newPinEnc) |
		ctap_param_to_mask(CTAP_clientPIN_pinUvAuthParam);
	if (!ctap_is_present(cp->present, mandatory_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// 5.3 (5.7) Check the remaining pin attempts (total and boot).
	ctap_check(check_pin_remaining_attempts(state));

	// 5.4 The authenticator calls decapsulate on the provided platform key-agreement key
	//     to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, &cp->keyAgreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 5.5 The authenticator calls verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
	//     If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	uint8_t verify_ctx[pin_protocol->verify_get_context_size(pin_protocol)];
	pin_protocol->verify_init_with_shared_secret(pin_protocol, &verify_ctx, shared_secret);
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* msg part 1 */ cp->newPinEnc.data, cp->newPinEnc.size);
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* msg part 2 */ cp->pinHashEnc.data, cp->pinHashEnc.size);
	if (pin_protocol->verify_final(pin_protocol, &verify_ctx, cp->pinUvAuthParam.data, cp->pinUvAuthParam.size) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// 5.6 - 5.8 Check the provided pin.
	ctap_check(check_pin_hash(state, pin_protocol, &cp->pinHashEnc, shared_secret));

	// 5.9 - 5.18 Set new pin.
	ctap_check(set_pin(state, pin_protocol, &cp->newPinEnc, shared_secret));

	// 5.19 Authenticator calls resetPinUvAuthToken() for all pinUvAuthProtocols supported
	//      by this authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
	ctap_all_pin_protocols_reset_pin_uv_auth_token(state);

	return CTAP2_OK;

}

static uint8_t get_pin_token_using_pin_with_permissions(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const COSE_Key *const key_agreement,
	const ctap_string_t *const pin_hash_enc,
	const uint32_t permissions,
	const CTAP_rpId *const rp_id,
	CborEncoder *encoder
) {

	uint8_t ret;

	// Check remaining pin attempts.
	ctap_check(check_pin_remaining_attempts(state));

	// The authenticator calls decapsulate on the provided platform key-agreement key
	// to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, key_agreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Check the provided pin.
	ctap_check(check_pin_hash(state, pin_protocol, pin_hash_enc, shared_secret));

	// TODO: Handle forcePINChange.

	// Create a new pinUvAuthToken by calling resetPinUvAuthToken()
	// for all pinUvAuthProtocols supported by this authenticator.
	// (I.e. all existing pinUvAuthTokens are invalidated.)
	ctap_all_pin_protocols_reset_pin_uv_auth_token(state);

	// Call beginUsingPinUvAuthToken(userIsPresent: false).
	ctap_pin_uv_auth_token_begin_using(state, false, permissions);
	// If the rpId parameter is present, associate the permissions RP ID with the pinUvAuthToken.
	if (rp_id != NULL) {
		ctap_compute_rp_id_hash(state->crypto, state->pin_uv_auth_token_state.rpId_hash, rp_id);
		state->pin_uv_auth_token_state.rpId_set = true;
		debug_log(
			"pinUvAuthToken RP ID set to '%.*s' hash = ",
			(int) rp_id->id.size, rp_id->id.data
		);
		dump_hex(state->pin_uv_auth_token_state.rpId_hash, sizeof(state->pin_uv_auth_token_state.rpId_hash));
	}

	// The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
	// i.e. encrypt(shared secret, pinUvAuthToken).

	const size_t encrypted_pin_uv_auth_token_length =
		sizeof(pin_protocol->pin_uv_auth_token)
		+ pin_protocol->encryption_extra_length;
	uint8_t encrypted_pin_uv_auth_token[encrypted_pin_uv_auth_token_length];
	if (pin_protocol->encrypt(
		pin_protocol,
		shared_secret,
		pin_protocol->pin_uv_auth_token, sizeof(pin_protocol->pin_uv_auth_token),
		encrypted_pin_uv_auth_token
	) != 0) {
		assert(false);
		return CTAP1_ERR_OTHER;
	}

	CborEncoder map;
	CborError err;

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));
	// 2. pinUvAuthToken
	cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_pinUvAuthToken));
	cbor_encoding_check(cbor_encode_byte_string(&map, encrypted_pin_uv_auth_token, encrypted_pin_uv_auth_token_length));
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

uint8_t ctap_client_pin_get_pin_token(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const CTAP_clientPIN *const cp,
	CborEncoder *const encoder
) {

	// 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)

	// If the authenticator does not receive mandatory parameters for this command,
	// it returns CTAP2_ERR_MISSING_PARAMETER error.
	const uint32_t mandatory_params =
		ctap_param_to_mask(CTAP_clientPIN_keyAgreement) |
		ctap_param_to_mask(CTAP_clientPIN_pinHashEnc);
	if (!ctap_is_present(cp->present, mandatory_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// If authenticatorClientPIN's permissions parameter is present in the getPinToken (0x05) subcommand,
	// return CTAP1_ERR_INVALID_PARAMETER.
	// If authenticatorClientPIN's rpId parameter is present in the getPinToken (0x05) subcommand,
	// return CTAP1_ERR_INVALID_PARAMETER.
	const uint32_t extraneous_params =
		ctap_param_to_mask(CTAP_clientPIN_permissions) |
		ctap_param_to_mask(CTAP_clientPIN_rpId);
	if (ctap_is_present_some(cp->present, extraneous_params)) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	return get_pin_token_using_pin_with_permissions(
		state,
		pin_protocol,
		&cp->keyAgreement,
		&cp->pinHashEnc,
		// If the noMcGaPermissionsWithClientPin option ID is present and set to false, or absent
		// (LionKey's case, see ctap_get_info()), then assign the pinUvAuthToken the default permissions (mc and ga).
		CTAP_clientPIN_pinUvAuthToken_permission_mc | CTAP_clientPIN_pinUvAuthToken_permission_ga,
		// Note that the permissions RP ID is not set even though it is required for mc and ga permissions.
		// It will be set on first use of the pinUvAuthToken with an RP ID.
		NULL,
		encoder
	);

}

uint8_t ctap_client_pin_get_pin_uv_auth_token_using_pin_with_permissions(
	ctap_state_t *const state,
	ctap_pin_protocol_t *const pin_protocol,
	const CTAP_clientPIN *const cp,
	CborEncoder *const encoder
) {

	// 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)

	// If the authenticator does not receive mandatory parameters for this command,
	// it returns CTAP2_ERR_MISSING_PARAMETER error.
	const uint32_t mandatory_params =
		ctap_param_to_mask(CTAP_clientPIN_keyAgreement) |
		ctap_param_to_mask(CTAP_clientPIN_pinHashEnc) |
		ctap_param_to_mask(CTAP_clientPIN_permissions);
	if (!ctap_is_present(cp->present, mandatory_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// If the authenticator receives a permissions parameter with value 0, return CTAP1_ERR_INVALID_PARAMETER.
	if (cp->permissions == 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// The following checks are implied by the pinUvAuthToken permissions definition
	// (the table in 6.5.5.7. Operations to Obtain a pinUvAuthToken)
	const uint32_t permissions_that_require_rp_id =
		CTAP_clientPIN_pinUvAuthToken_permission_mc
		| CTAP_clientPIN_pinUvAuthToken_permission_ga;
	const bool rpId_required = ctap_permissions_include_any_of(cp->permissions, permissions_that_require_rp_id);
	const bool rpId_present = ctap_param_is_present(cp, CTAP_clientPIN_rpId);
	if (rpId_required && !rpId_present) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// For each pinUvAuthToken permission present in the permissions parameter,
	// if the statement corresponding to the permission is currently true,
	// terminate these steps and return CTAP2_ERR_UNAUTHORIZED_PERMISSION.
	// Undefined permissions present in the permissions parameter are ignored.
	// enum AuthenticatorOption {
	// 	OptionFalse = -1,
	// 	OptionAbsent = 0,
	// 	OptionTrue = 1,
	// };
	// const enum AuthenticatorOption noMcGaPermissionsWithClientPin = OptionAbsent;
	// const enum AuthenticatorOption credMgmt = OptionTrue;
	// const enum AuthenticatorOption bioEnroll = OptionAbsent;
	// const enum AuthenticatorOption largeBlobs = OptionAbsent;
	// const enum AuthenticatorOption authnrCfg = OptionTrue;
	// if (
	// 	(
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_mc)
	// 		&& noMcGaPermissionsWithClientPin == OptionTrue
	// 	)
	// 	|| (
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_ga)
	// 		&& noMcGaPermissionsWithClientPin == OptionTrue
	// 	)
	// 	|| (
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_cm)
	// 		&& (credMgmt == OptionFalse || credMgmt == OptionAbsent)
	// 	)
	// 	|| (
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_be)
	// 		&& bioEnroll == OptionAbsent
	// 	)
	// 	|| (
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_lbw)
	// 		&& (largeBlobs == OptionFalse || largeBlobs == OptionAbsent)
	// 	)
	// 	|| (
	// 		permissions_include_any_of(cp->permissions, CTAP_clientPIN_pinUvAuthToken_permission_acfg)
	// 		&& (authnrCfg == OptionFalse || authnrCfg == OptionAbsent)
	// 	)
	// 	) {
	// 	return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
	// }
	// simplified constant version
	if (ctap_permissions_include_any_of(
		cp->permissions,
		CTAP_clientPIN_pinUvAuthToken_permission_be
		| CTAP_clientPIN_pinUvAuthToken_permission_lbw
	)) {
		return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
	}

	return get_pin_token_using_pin_with_permissions(
		state,
		pin_protocol,
		&cp->keyAgreement,
		&cp->pinHashEnc,
		// Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
		// Note: We do not clear the undefined (unknown) permissions since their presence does not affect anything.
		cp->permissions,
		// If the rpId parameter is present, associate the permissions RP ID with the pinUvAuthToken.
		rpId_present ? &cp->rpId : NULL,
		encoder
	);

}

uint8_t ctap_get_pin_protocol(ctap_state_t *state, size_t protocol_version, ctap_pin_protocol_t **pin_protocol) {
	debug_log("ctap_get_pin_protocol: protocol_version=%" PRIsz nl, protocol_version);
	const size_t max_protocol_version = sizeof(state->pin_protocols) / sizeof(ctap_pin_protocol_t);
	assert(max_protocol_version <= 2);
	if (protocol_version < 1 || protocol_version > max_protocol_version) {
		// protocol version not supported
		return CTAP1_ERR_INVALID_PARAMETER;
	}
	*pin_protocol = &state->pin_protocols[protocol_version - 1];
	return CTAP2_OK;
}

uint8_t ctap_client_pin(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	uint8_t ret;
	CborError err;

	CTAP_clientPIN cp;
	ctap_check(ctap_parse_client_pin(it, &cp));

	ctap_pin_protocol_t *pin_protocol;
	ctap_check(ctap_get_pin_protocol(state, cp.pinUvAuthProtocol, &pin_protocol));

	CborEncoder map;

	switch (cp.subCommand) {

		case CTAP_clientPIN_subCmd_getPINRetries:
			debug_log(magenta("CTAP_clientPIN_subCmd_getPINRetries") nl);
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));
			// 1. pinRetries
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_pinRetries));
			cbor_encoding_check(cbor_encode_int(&map, ctap_get_pin_total_remaining_attempts(state)));
			// 2. powerCycleState
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_powerCycleState));
			// Present and true if the authenticator requires a power cycle
			// before any future PIN operation, false if no power cycle needed.
			// If the field is omitted, no information is given
			// about whether a power cycle is needed or not.
			bool power_cycle_needed = state->pin_boot_remaining_attempts == 0;
			cbor_encoding_check(cbor_encode_boolean(&map, power_cycle_needed));
			// close response map
			cbor_encoding_check(cbor_encoder_close_container(encoder, &map));
			return CTAP2_OK;

		case CTAP_clientPIN_subCmd_getKeyAgreement:
			debug_log(magenta("CTAP_clientPIN_subCmd_getKeyAgreement") nl);
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));
			// 1. keyAgreement
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_keyAgreement));
			ctap_check(pin_protocol->get_public_key(pin_protocol, &map));
			// close response map
			cbor_encoding_check(cbor_encoder_close_container(encoder, &map));
			return CTAP2_OK;

		case CTAP_clientPIN_subCmd_setPIN:
			debug_log(magenta("CTAP_clientPIN_subCmd_setPIN") nl);
			return ctap_client_pin_set_pin(state, pin_protocol, &cp);

		case CTAP_clientPIN_subCmd_changePIN:
			debug_log(magenta("CTAP_clientPIN_subCmd_changePIN") nl);
			return ctap_client_pin_change_pin(state, pin_protocol, &cp);

		case CTAP_clientPIN_subCmd_getPinToken:
			debug_log(magenta("CTAP_clientPIN_subCmd_getPinToken") nl);
			return ctap_client_pin_get_pin_token(state, pin_protocol, &cp, encoder);

		case CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingUvWithPermissions:
		case CTAP_clientPIN_subCmd_getUVRetries:
			// not applicable because we currently don't support any built-in user verification methods
			// (see the uv option in the authenticatorGetInfo response)
			return CTAP2_ERR_INVALID_SUBCOMMAND;

		case CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingPinWithPermissions:
			debug_log(magenta("CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingPinWithPermissions") nl);
			return ctap_client_pin_get_pin_uv_auth_token_using_pin_with_permissions(state, pin_protocol, &cp, encoder);

	}

	// default case (unknown or unsupported subcommand)
	return CTAP2_ERR_INVALID_SUBCOMMAND;

}
