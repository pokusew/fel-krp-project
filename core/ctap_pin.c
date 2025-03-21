#include "ctap_pin.h"
#include "utils.h"
#include <uECC.h>
#include <hmac.h>
#include <aes.h>

/**
 * This function prepares the pinUvAuthToken for use by the platform,
 * which has invoked one of the pinUvAuthToken-issuing operations,
 * by setting particular pinUvAuthToken state variables to given use-case-specific values.
 * See also 6.5.5.7 Operations to Obtain a pinUvAuthToken.
 */
void ctap_pin_uv_auth_token_begin_using(ctap_pin_uv_auth_token_state *token_state, bool user_is_present) {
	token_state->user_present = user_is_present;
	token_state->user_verified = true;
	token_state->initial_usage_time_limit = CTAP_PIN_UV_AUTH_TOKEN_STATE_INITIAL_USAGE_TIME_LIMIT_USB;
	token_state->user_present_time_limit = CTAP_PIN_UV_AUTH_TOKEN_STATE_INITIAL_USAGE_TIME_LIMIT_USB;
	token_state->max_usage_time_period = 10 * 60 * 1000; // 10 minutes
	token_state->usage_timer.start = /* TODO: getCurrentTimestamp() */ 0;
	token_state->usage_timer.running = true;
	token_state->in_use = true;
}

void ctap_pin_uv_auth_token_usage_timer_observer(ctap_pin_uv_auth_token_state *token_state) {
	ctap_timer *usage_timer = &token_state->usage_timer;
	if (!usage_timer->running) {
		return;
	}
	uint32_t elapsed = /* TODO: getCurrentTimestamp() */ 1 - usage_timer->start;
	if (elapsed > token_state->max_usage_time_period) {
		ctap_pin_uv_auth_token_stop_using(token_state);
		return;
	}
	if (elapsed > token_state->initial_usage_time_limit) {
		ctap_pin_uv_auth_token_stop_using(token_state);
		return;
	}
	if (elapsed > token_state->user_present_time_limit) {
		ctap_pin_uv_auth_token_clear_user_present_flag(token_state);
	}
}

bool ctap_pin_uv_auth_token_get_user_present_flag_value(ctap_pin_uv_auth_token_state *token_state) {
	return token_state->in_use ? token_state->user_present : false;
}

bool ctap_pin_uv_auth_token_get_user_verified_flag_value(ctap_pin_uv_auth_token_state *token_state) {
	return token_state->in_use ? token_state->user_verified : false;
}

void ctap_pin_uv_auth_token_clear_user_present_flag(ctap_pin_uv_auth_token_state *token_state) {
	if (token_state->in_use) {
		token_state->user_present = false;
	}
}

void ctap_pin_uv_auth_token_clear_permissions_except_lbw(ctap_pin_uv_auth_token_state *token_state) {
	if (token_state->in_use) {
		token_state->permissions = token_state->permissions & CTAP_clientPIN_pinUvAuthToken_permission_lbw;
	}
}

void ctap_pin_uv_auth_token_stop_using(ctap_pin_uv_auth_token_state *token_state) {
	token_state->in_use = false;
	token_state->rpId = 0;
	token_state->rpIdSet = false;
	token_state->permissions = 0;
	token_state->usage_timer.running = false;
	token_state->usage_timer.start = 0;
	token_state->initial_usage_time_limit = 0;
	token_state->user_present_time_limit = 0;
	token_state->max_usage_time_period = 0;
	token_state->user_verified = false;
	token_state->user_present = false;
}

static int ctap_pin_protocol_v1_initialize(
	ctap_pin_protocol_t *protocol
) {
	int ret = 0;
	ret |= protocol->regenerate(protocol);
	ret |= protocol->reset_pin_uv_auth_token(protocol);
	return ret;
}

static int ctap_pin_protocol_v1_regenerate(
	ctap_pin_protocol_t *protocol
) {
	// Generate a fresh, random P-256 private key, x, and compute the associated public point.

	static_assert(
		sizeof(protocol->key_agreement_private_key) == 32,
		"unexpected sizeof(protocol->key_agreement_private_key)"
	);
	ctap_generate_rng(
		protocol->key_agreement_private_key,
		sizeof(protocol->key_agreement_private_key)
	);
	debug_log("key_agreement_private_key = ");
	dump_hex(protocol->key_agreement_private_key, sizeof(protocol->key_agreement_private_key));

	if (uECC_compute_public_key(
		protocol->key_agreement_private_key,
		protocol->key_agreement_public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return 0;
	}

	return 1;
}

static int ctap_pin_protocol_v1_reset_pin_uv_auth_token(
	ctap_pin_protocol_t *protocol
) {
	ctap_generate_rng(
		protocol->pin_uv_auth_token,
		sizeof(protocol->pin_uv_auth_token)
	);
	debug_log("v1 pinUvAuthToken = ");
	dump_hex(protocol->pin_uv_auth_token, sizeof(protocol->pin_uv_auth_token));
	return 0;
}

static int ctap_pin_protocol_v1_get_public_key(
	ctap_pin_protocol_t *protocol,
	CborEncoder *encoder
) {

	const uint8_t *x = protocol->key_agreement_public_key;
	const uint8_t *y = protocol->key_agreement_public_key + 32;

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 5));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_KTY));
	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_KTY_EC2));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_ALG));
	cbor_encoding_check(cbor_encode_int(&map, COSE_ALG_ECDH_ES_HKDF_256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_CRV));
	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_CRV_P256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_X));
	cbor_encoding_check(cbor_encode_byte_string(&map, x, 32));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_Y));
	cbor_encoding_check(cbor_encode_byte_string(&map, y, 32));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}


static int ctap_pin_protocol_v1_decapsulate(
	const ctap_pin_protocol_t *protocol,
	const COSE_Key *peer_cose_key,
	uint8_t shared_secret[32]
) {
	// 6.5.6. PIN/UV Auth Protocol One
	//
	// decapsulate(peerCoseKey) → sharedSecret | error
	//   1. Return ecdh(peerCoseKey).
	//
	// ecdh(peerCoseKey) → sharedSecret | error
	//   1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
	//      If unsuccessful, or if the resulting point is not on the curve, return error.
	//   2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
	//      with the local private key agreement key.)
	//   3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
	//   4. Return kdf(Z).
	//
	// kdf(Z) → sharedSecret
	//   Return SHA-256(Z).

	if (uECC_shared_secret(
		(uint8_t *) &peer_cose_key->pubkey,
		protocol->key_agreement_private_key,
		shared_secret,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_shared_secret failed" nl);
		return 1;
	}

	SHA256_CTX sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, shared_secret, 32);
	sha256_final(&sha256_ctx, shared_secret);

	return 0;
}

static int ctap_pin_protocol_v1_encrypt(
	const uint8_t *shared_secret,
	const uint8_t *plaintext, const size_t plaintext_length,
	uint8_t *ciphertext
) {
	if (plaintext_length % AES_BLOCKLEN != 0) {
		return 1;
	}

	uint8_t all_zero_iv[AES_BLOCKLEN];
	memset(all_zero_iv, 0, AES_BLOCKLEN);
	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, shared_secret, all_zero_iv);
	memcpy(ciphertext, plaintext, plaintext_length);
	AES_CBC_decrypt_buffer(&aes_ctx, ciphertext, plaintext_length);

	return 0;
}

static int ctap_pin_protocol_v1_decrypt(
	const uint8_t *shared_secret,
	const uint8_t *ciphertext, const size_t ciphertext_length,
	uint8_t *plaintext
) {
	if (ciphertext_length % AES_BLOCKLEN != 0) {
		return 1;
	}

	uint8_t all_zero_iv[AES_BLOCKLEN];
	memset(all_zero_iv, 0, AES_BLOCKLEN);
	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, shared_secret, all_zero_iv);
	memcpy(plaintext, ciphertext, ciphertext_length);
	AES_CBC_decrypt_buffer(&aes_ctx, plaintext, ciphertext_length);

	return 0;
}

static void ctap_pin_protocol_v1_verify_init(
	const ctap_pin_protocol_t *protocol,
	hmac_sha256_ctx_t *hmac_sha256_ctx,
	const uint8_t *key, const size_t key_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) → success | error
	//   1. TODO: If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.
	hmac_sha256_init(hmac_sha256_ctx, key, key_length);
}


static void ctap_pin_protocol_v1_verify_update(
	const ctap_pin_protocol_t *protocol,
	hmac_sha256_ctx_t *hmac_sha256_ctx,
	const uint8_t *message_data, const size_t message_data_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) → success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.
	hmac_sha256_update(hmac_sha256_ctx, message_data, message_data_length);
}


static int ctap_pin_protocol_v1_verify_final(
	const ctap_pin_protocol_t *protocol,
	hmac_sha256_ctx_t *hmac_sha256_ctx,
	const uint8_t *signature, const size_t signature_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) → success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.
	uint8_t hmac[32];
	hmac_sha256_final(hmac_sha256_ctx, hmac);
	if (signature_length != 16 || memcmp(hmac, signature, 16) != 0) {
		return 1;
	}
	return 0;
}


void ctap_pin_protocol_v1_init(ctap_pin_protocol_t *protocol) {

	protocol->shared_secret_length = 32;
	protocol->encryption_extra_length = 0;

	protocol->initialize = ctap_pin_protocol_v1_initialize;
	protocol->regenerate = ctap_pin_protocol_v1_regenerate;
	protocol->reset_pin_uv_auth_token = ctap_pin_protocol_v1_reset_pin_uv_auth_token;
	protocol->get_public_key = ctap_pin_protocol_v1_get_public_key;
	protocol->decapsulate = ctap_pin_protocol_v1_decapsulate;
	protocol->encrypt = ctap_pin_protocol_v1_encrypt;
	protocol->decrypt = ctap_pin_protocol_v1_decrypt;
	protocol->verify_init = ctap_pin_protocol_v1_verify_init;
	protocol->verify_update = ctap_pin_protocol_v1_verify_update;
	protocol->verify_final = ctap_pin_protocol_v1_verify_final;

	// TODO: handle initialize error
	protocol->initialize(protocol);

}

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

static void decrement_pin_remaining_attempts(ctap_state_t *state) {
	assert(state->persistent.pin_total_remaining_attempts > 0);
	assert(state->pin_boot_remaining_attempts > 0);
	state->persistent.pin_total_remaining_attempts--;
	state->pin_boot_remaining_attempts--;
}

static void reset_pin_remaining_attempts(ctap_state_t *state) {
	state->persistent.pin_total_remaining_attempts = PIN_TOTAL_ATTEMPTS;
	state->pin_boot_remaining_attempts = PIN_PER_BOOT_ATTEMPTS;
}

static uint8_t check_pin_remaining_attempts(ctap_state_t *state) {
	if (state->persistent.pin_total_remaining_attempts == 0) {
		return CTAP2_ERR_PIN_BLOCKED;
	}
	if (state->pin_boot_remaining_attempts == 0) {
		return CTAP2_ERR_PIN_AUTH_BLOCKED;
	}
	return CTAP2_OK;
}

static uint8_t handle_invalid_pin(ctap_state_t *state, ctap_pin_protocol_t *pin_protocol) {
	decrement_pin_remaining_attempts(state);
	pin_protocol->regenerate(pin_protocol);
	uint8_t status = check_pin_remaining_attempts(state);
	if (status != CTAP2_OK) {
		return status;
	}
	return CTAP2_ERR_PIN_INVALID;
}

static uint8_t check_pin_hash(
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp,
	const uint8_t *shared_secret
) {
	// These preconditions should be ensured by the caller function.
	assert(state->persistent.pin_total_remaining_attempts > 0);
	assert(state->pin_boot_remaining_attempts > 0);

	// Note: This case is not explicitly mentioned in the spec.
	if (!state->persistent.is_pin_set) {
		return CTAP2_ERR_PIN_NOT_SET;
	}

	// The spec suggests, that we should decrement the pinRetries counter.
	// by 1 BEFORE actually checking the pin. Then, if the pin is correct,
	// we should reset the pinRetries counter to the maximum value.
	// To avoid the unnecessary decrement/reset, we decrement the pinRetries counter
	// ONLY IF that pin is actually incorrect (in handle_invalid_pin).

	// Authenticator decrypts pinHashEnc using decrypt(shared secret, pinHashEnc)
	// and verifies against its internal stored LEFT(SHA-256(curPin), 16).
	size_t pin_hash_length = cp->pinHashEncSize - pin_protocol->encryption_extra_length;
	assert(sizeof(state->persistent.pin_hash) <= pin_hash_length);
	uint8_t pin_hash[pin_hash_length];
	if (pin_protocol->decrypt(
		/* key */ shared_secret,
		/* ciphertext */ cp->pinHashEnc, cp->pinHashEncSize,
		/* output: plaintext */ pin_hash
	) != 0) {
		return handle_invalid_pin(state, pin_protocol);
	}
	if (memcmp(state->persistent.pin_hash, pin_hash, sizeof(state->persistent.pin_hash)) != 0) {
		return handle_invalid_pin(state, pin_protocol);
	}

	// 5.8 Authenticator sets the pinRetries counter to maximum value.
	reset_pin_remaining_attempts(state);

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
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp,
	const uint8_t *shared_secret
) {

	// 6.5.5.5. Setting a New PIN:     5.7
	// 6.5.5.6. Changing existing PIN: 5.10
	//   If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER
	size_t padded_new_pin_length = cp->newPinEncSize - pin_protocol->encryption_extra_length;
	if (padded_new_pin_length != 64) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 6.5.5.5. Setting a New PIN:     5.6
	// 6.5.5.6. Changing existing PIN: 5.9
	//   The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
	//   If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	uint8_t padded_new_pin[64];
	if (pin_protocol->decrypt(
		/* key */ shared_secret,
		/* ciphertext */ cp->newPinEnc, cp->newPinEncSize,
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
	// Note: This case (and error code) is not explicitly stated in the spec.
	if (new_pin_length > 63) {
		return CTAP1_ERR_INVALID_PARAMETER;
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
	size_t new_pin_code_point_length = count_unicode_code_points_in_utf8_string(new_pin, new_pin_length);
	if (new_pin_code_point_length < 4) {
		return CTAP2_ERR_PIN_POLICY_VIOLATION;
	}
	assert(new_pin_code_point_length <= 63);

	// 6.5.5.5. Setting a New PIN:     5.11, 5.12
	// 6.5.5.6. Changing existing PIN: 5.15, 5.17
	//   Authenticator remembers newPin length internally as PINCodePointLength.
	//   Authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
	//   sets the pinRetries counter to maximum count, and returns CTAP2_OK.

	uint8_t new_pin_hash[32];
	SHA256_CTX sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, new_pin, new_pin_length);
	sha256_final(&sha256_ctx, new_pin_hash);

	// CurrentStoredPIN = LEFT(SHA-256(newPin), 16)
	static_assert(
		PIN_HASH_SIZE <= sizeof(new_pin_hash),
		"PIN_HASH_SIZE must be greater than 32 bytes (the size of the SHA-256 output)"
	);
	memcpy(state->persistent.pin_hash, new_pin_hash, PIN_HASH_SIZE);
	state->persistent.pin_code_point_length = new_pin_code_point_length;
	state->persistent.is_pin_set = true;

	reset_pin_remaining_attempts(state);

	return CTAP2_OK;

}

uint8_t ctap_client_pin_set_pin(
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp
) {

	// 6.5.5.5 Setting a New PIN

	// 5.1 If the authenticator does not receive mandatory parameters for this command,
	//     it returns CTAP2_ERR_MISSING_PARAMETER error.
	if (!cp->keyAgreementPresent || cp->newPinEncSize == 0 || cp->pinUvAuthParamSize == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// 5.3 If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
	if (state->persistent.is_pin_set) {
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
	hmac_sha256_ctx_t verify_ctx;
	pin_protocol->verify_init(pin_protocol, &verify_ctx, /* key */ shared_secret, sizeof(shared_secret));
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* message */ cp->newPinEnc, cp->newPinEncSize);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ cp->pinUvAuthParam, cp->pinUvAuthParamSize
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	return set_pin(state, pin_protocol, cp, shared_secret);

}

uint8_t ctap_client_pin_change_pin(
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp
) {

	uint8_t status;

	// 6.5.5.6. Changing existing PIN

	// 5.1 If the authenticator does not receive mandatory parameters for this command,
	//     it returns CTAP2_ERR_MISSING_PARAMETER error.
	if (!cp->keyAgreementPresent || cp->newPinEncSize == 0 || cp->pinUvAuthParamSize == 0 || cp->pinHashEncSize == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// 5.3 (5.7) Check the remaining pin attempts (total and boot).
	if ((status = check_pin_remaining_attempts(state)) != CTAP2_OK) {
		return status;
	}

	// 5.4 The authenticator calls decapsulate on the provided platform key-agreement key
	//     to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, &cp->keyAgreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 5.5 The authenticator calls verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
	//     If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	hmac_sha256_ctx_t verify_ctx;
	pin_protocol->verify_init(pin_protocol, &verify_ctx, /* key */ shared_secret, sizeof(shared_secret));
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* message part 1 */ cp->newPinEnc, cp->newPinEncSize);
	pin_protocol->verify_update(pin_protocol, &verify_ctx, /* message part 2 */ cp->pinHashEnc, cp->pinHashEncSize);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ cp->pinUvAuthParam, cp->pinUvAuthParamSize
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// 5.6 - 5.8 Check the provided pin.
	if ((status = check_pin_hash(state, pin_protocol, cp, shared_secret)) != CTAP2_OK) {
		return status;
	}

	// 5.9 - 5.18 Set new pin.
	if ((status = set_pin(state, pin_protocol, cp, shared_secret)) != CTAP2_OK) {
		return status;
	}

	// 5.19 Authenticator calls resetPinUvAuthToken() for all pinUvAuthProtocols supported
	//      by this authenticator. (I.e. all existing pinUvAuthTokens are invalidated.)
	state->pin_protocol[0].initialize(&state->pin_protocol[0]);

	return CTAP2_OK;

}

uint8_t ctap_client_pin_get_pin_token(
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp
) {

	uint8_t status;

	// 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)

	// If the authenticator does not receive mandatory parameters for this command,
	// it returns CTAP2_ERR_MISSING_PARAMETER error.
	if (!cp->keyAgreementPresent || cp->pinHashEncSize == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// If authenticatorClientPIN's permissions parameter is present in the getPinToken (0x05) subcommand,
	// return CTAP1_ERR_INVALID_PARAMETER.
	// If authenticatorClientPIN's rpId parameter is present in the getPinToken (0x05) subcommand,
	// return CTAP1_ERR_INVALID_PARAMETER.
	if (cp->permissionsPresent || cp->rpIdPresent) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Check remaining pin attempts.
	if ((status = check_pin_remaining_attempts(state)) != CTAP2_OK) {
		return status;
	}

	// The authenticator calls decapsulate on the provided platform key-agreement key
	// to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, &cp->keyAgreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Check the provided pin.
	if ((status = check_pin_hash(state, pin_protocol, cp, shared_secret)) != CTAP2_OK) {
		return status;
	}

	// TODO: Handle forcePINChange.

	// Create a new pinUvAuthToken by calling resetPinUvAuthToken()
	// for all pinUvAuthProtocols supported by this authenticator.
	// (I.e. all existing pinUvAuthTokens are invalidated.)
	state->pin_protocol[0].reset_pin_uv_auth_token(&state->pin_protocol[0]);

	// Call beginUsingPinUvAuthToken(userIsPresent: false).
	ctap_pin_uv_auth_token_begin_using(&state->pin_uv_auth_token_state, false);
	// If the noMcGaPermissionsWithClientPin option ID is present and set to false, or absent,
	// then assign the pinUvAuthToken the default permissions (mc and ga).
	// Note that the permissions RP ID is not set even though it is required for mc and ga permissions.
	// It will be set on first use of the pinUvAuthToken with an RP ID.
	state->pin_uv_auth_token_state.permissions =
		CTAP_clientPIN_pinUvAuthToken_permission_mc | CTAP_clientPIN_pinUvAuthToken_permission_ga;

	// The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
	// i.e. encrypt(shared secret, pinUvAuthToken).

	size_t encrypted_pin_uv_auth_token_length = sizeof(pin_protocol->pin_uv_auth_token) + pin_protocol->encryption_extra_length;
	uint8_t encrypted_pin_uv_auth_token[encrypted_pin_uv_auth_token_length];
	if (pin_protocol->encrypt(
		shared_secret,
		pin_protocol->pin_uv_auth_token, sizeof(pin_protocol->pin_uv_auth_token),
		encrypted_pin_uv_auth_token
	) != 0) {
		assert(false);
		return CTAP1_ERR_OTHER;
	}

	CborEncoder *encoder = &state->response.encoder;
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

uint8_t ctap_client_pin_get_pin_uv_auth_token_using_pin_pin_with_permissions(
	ctap_state_t *state,
	ctap_pin_protocol_t *pin_protocol,
	const CTAP_clientPIN *cp
) {

	uint8_t status;

	// 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)

	// If the authenticator does not receive mandatory parameters for this command,
	// it returns CTAP2_ERR_MISSING_PARAMETER error.
	if (!cp->keyAgreementPresent || cp->pinHashEncSize == 0 || cp->permissionsPresent == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// If the authenticator receives a permissions parameter with value 0, return CTAP1_ERR_INVALID_PARAMETER.
	if (cp->permissions == 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// The following checks are implied by the pinUvAuthToken permissions definition
	// (the table in 6.5.5.7. Operations to Obtain a pinUvAuthToken)
	const bool rpIdRequired = permissions_include_any_of(
		cp->permissions,
		CTAP_clientPIN_pinUvAuthToken_permission_mc
		| CTAP_clientPIN_pinUvAuthToken_permission_ga
	);
	if (rpIdRequired && !cp->rpIdPresent) {
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
	if (permissions_include_any_of(
		cp->permissions,
		CTAP_clientPIN_pinUvAuthToken_permission_be
		| CTAP_clientPIN_pinUvAuthToken_permission_lbw
	)) {
		return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
	}

	// Check remaining pin attempts.
	if ((status = check_pin_remaining_attempts(state)) != CTAP2_OK) {
		return status;
	}

	// The authenticator calls decapsulate on the provided platform key-agreement key
	// to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	uint8_t shared_secret[pin_protocol->shared_secret_length];
	if (pin_protocol->decapsulate(pin_protocol, &cp->keyAgreement, shared_secret) != 0) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Check the provided pin.
	if ((status = check_pin_hash(state, pin_protocol, cp, shared_secret)) != CTAP2_OK) {
		return status;
	}

	// TODO: Handle forcePINChange.

	// Create a new pinUvAuthToken by calling resetPinUvAuthToken()
	// for all pinUvAuthProtocols supported by this authenticator.
	// (I.e. all existing pinUvAuthTokens are invalidated.)
	state->pin_protocol[0].reset_pin_uv_auth_token(&state->pin_protocol[0]);

	// Call beginUsingPinUvAuthToken(userIsPresent: false).
	ctap_pin_uv_auth_token_begin_using(&state->pin_uv_auth_token_state, false);
	// Assign the requested permissions to the pinUvAuthToken, ignoring any undefined permissions.
	// Note: We do not clear the undefined (unknown) permissions since their presence does not affect anything.
	state->pin_uv_auth_token_state.permissions = cp->permissions;
	// If the rpId parameter is present, associate the permissions RP ID with the pinUvAuthToken.
	if (cp->rpIdPresent) {
		state->pin_uv_auth_token_state.rpId = cp->rpId;
		state->pin_uv_auth_token_state.rpIdSet = true;
	}

	// The authenticator returns the encrypted pinUvAuthToken for the specified pinUvAuthProtocol,
	// i.e. encrypt(shared secret, pinUvAuthToken).

	size_t encrypted_pin_uv_auth_token_length = sizeof(pin_protocol->pin_uv_auth_token) + pin_protocol->encryption_extra_length;
	uint8_t encrypted_pin_uv_auth_token[encrypted_pin_uv_auth_token_length];
	if (pin_protocol->encrypt(
		shared_secret,
		pin_protocol->pin_uv_auth_token, sizeof(pin_protocol->pin_uv_auth_token),
		encrypted_pin_uv_auth_token
	) != 0) {
		assert(false);
		return CTAP1_ERR_OTHER;
	}

	CborEncoder *encoder = &state->response.encoder;
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

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CTAP_clientPIN cp;
	uint8_t status = ctap_parse_client_pin(request, length, &cp);
	if (status != CTAP2_OK) {
		return status;
	}

	if (cp.pinUvAuthProtocol != 1 && cp.pinUvAuthProtocol != 2) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	static_assert(
		(sizeof(state->pin_protocol) / sizeof(ctap_pin_protocol_t)) == 2,
		"unexpected state->pin_protocol array length"
	);
	assert(
		0 <= cp.pinUvAuthProtocol - 1
		&& cp.pinUvAuthProtocol - 1 < (sizeof(state->pin_protocol) / sizeof(ctap_pin_protocol_t))
	);
	ctap_pin_protocol_t *pin_protocol = &state->pin_protocol[cp.pinUvAuthProtocol - 1];

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;

	switch (cp.subCommand) {

		case CTAP_clientPIN_subCmd_getPINRetries:
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));
			// 1. pinRetries
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_pinRetries));
			cbor_encoding_check(cbor_encode_int(&map, state->persistent.pin_total_remaining_attempts));
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
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));
			// 1. keyAgreement
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_keyAgreement));
			if ((ret = pin_protocol->get_public_key(pin_protocol, &map)) != CTAP2_OK) {
				return ret;
			}
			// close response map
			cbor_encoding_check(cbor_encoder_close_container(encoder, &map));
			return CTAP2_OK;

		case CTAP_clientPIN_subCmd_setPIN:
			return ctap_client_pin_set_pin(state, pin_protocol, &cp);

		case CTAP_clientPIN_subCmd_changePIN:
			return ctap_client_pin_change_pin(state, pin_protocol, &cp);

		case CTAP_clientPIN_subCmd_getPinToken:
			return ctap_client_pin_get_pin_token(state, pin_protocol, &cp);

		case CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingUvWithPermissions:
		case CTAP_clientPIN_subCmd_getUVRetries:
			// not applicable because we currently don't support any built-in user verification methods
			// (see the uv option in the authenticatorGetInfo response)
			return CTAP2_ERR_INVALID_SUBCOMMAND;

		case CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingPinWithPermissions:
			return ctap_client_pin_get_pin_uv_auth_token_using_pin_pin_with_permissions(state, pin_protocol, &cp);

	}

	// default case (unknown or unsupported subcommand)
	return CTAP2_ERR_INVALID_SUBCOMMAND;

}
