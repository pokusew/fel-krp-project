#include "ctap.h"
#include <uECC.h>

/**
 * Converts an ES256 raw signature (64 bytes: r|s)
 * to an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3.
 *
 * WebAuthn 6.5.5. Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures
 * https://w3c.github.io/webauthn/#sctn-signature-attestation-types
 * For COSEAlgorithmIdentifier -7 (ES256), and other ECDSA-based algorithms,
 * the sig value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3.
 *
 * The ASN.1 structure is:
 * Ecdsa-Sig-Value ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 *
 * @param signature input raw signature (r|s), must be 64 bytes
 * @param asn1_der_signature output buffer for the ASN.1 DER encoded signature,
 *                           must be at least 72 bytes to handle the worst case
 *                           (when padding is needed in both r and s)
 */
void ctap_convert_to_asn1_der_ecdsa_sig_value(
	const uint8_t *signature,
	uint8_t *asn1_der_signature,
	size_t *asn1_der_signature_size
) {

	// extract r and s values (each 32 bytes)
	const uint8_t *r = signature;
	const uint8_t *s = signature + 32;

	// calculate lengths and padding needed for r and s
	// padding is needed if the high bit of the first byte is set
	uint8_t r_pad = (r[0] & 0x80) ? 1 : 0;
	uint8_t s_pad = (s[0] & 0x80) ? 1 : 0;

	// skip leading zeros in r
	uint8_t r_leading_zeros = 0;
	while (r_leading_zeros < 32 && r[r_leading_zeros] == 0) {
		r_leading_zeros++;
	}
	// but keep one zero byte if the next byte has its high bit set
	if ((r_leading_zeros > 0 && r_leading_zeros < 32 && (r[r_leading_zeros] & 0x80)) || r_leading_zeros == 32) {
		r_leading_zeros--;
	}

	// skip leading zeros in s
	uint8_t s_leading_zeros = 0;
	while (s_leading_zeros < 32 && s[s_leading_zeros] == 0) {
		s_leading_zeros++;
	}
	// but keep one zero byte if the next byte has its high bit set
	if ((s_leading_zeros > 0 && s_leading_zeros < 32 && (s[s_leading_zeros] & 0x80)) || s_leading_zeros == 32) {
		s_leading_zeros--;
	}

	uint8_t r_len = 32 - r_leading_zeros + r_pad;
	uint8_t s_len = 32 - s_leading_zeros + s_pad;

	uint8_t seq_len = 2 + r_len + 2 + s_len;
	assert(seq_len < 128);

	uint8_t *p = asn1_der_signature;

	// write SEQUENCE tag
	*p++ = 0x30; // SEQUENCE tag
	*p++ = seq_len;

	// write INTEGER tag and length for r
	*p++ = 0x02; // INTEGER tag
	*p++ = r_len;
	// write r value (with padding if needed)
	if (r_pad) {
		*p++ = 0x00;  // Add padding byte
	}
	memcpy(p, r + r_leading_zeros, 32 - r_leading_zeros);
	p += 32 - r_leading_zeros;

	// write INTEGER tag and length for s
	*p++ = 0x02;  // INTEGER tag
	*p++ = s_len;
	// write s value (with padding if needed)
	if (s_pad) {
		*p++ = 0x00;  // Add padding byte
	}
	memcpy(p, s + s_leading_zeros, 32 - s_leading_zeros);
	p += 32 - s_leading_zeros;

	*asn1_der_signature_size = 2 + seq_len;
	assert((size_t) (p - asn1_der_signature) == *asn1_der_signature_size);

}

static inline bool is_option_present(const CTAP_makeCredential *mc, const uint8_t option) {
	return (mc->options_present & option) == option;
}

static inline bool get_option_value(const CTAP_makeCredential *mc, const uint8_t option) {
	return (mc->options_values & option) == option;
}

static inline bool get_option_value_or_false(const CTAP_makeCredential *mc, const uint8_t option) {
	return is_option_present(mc, option) ? get_option_value(mc, option) : false;
}

static inline uint8_t verify(
	ctap_state_t *state,
	const CTAP_makeCredential *mc,
	ctap_pin_protocol_t *pin_protocol
) {
	hmac_sha256_ctx_t verify_ctx;
	if (pin_protocol->verify_init_with_pin_uv_auth_token(
		pin_protocol,
		&verify_ctx,
		&state->pin_uv_auth_token_state
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	pin_protocol->verify_update(
		pin_protocol,
		&verify_ctx,
		/* message */ mc->clientDataHash, sizeof(mc->clientDataHash)
	);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ mc->pinUvAuthParam, mc->pinUvAuthParam_size
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	return CTAP2_OK;
}

static uint8_t encode_public_key(
	CborEncoder *encoder,
	const uint8_t *public_key
) {

	const uint8_t *x = public_key;
	const uint8_t *y = public_key + 32;

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 5));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_KTY));
	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_KTY_EC2));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_ALG));
	cbor_encoding_check(cbor_encode_int(&map, COSE_ALG_ES256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_CRV));
	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_CRV_P256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_X));
	cbor_encoding_check(cbor_encode_byte_string(&map, x, 32));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_Y));
	cbor_encoding_check(cbor_encode_byte_string(&map, y, 32));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static void auth_data_compute_rp_id_hash(CTAP_authenticator_data *auth_data, const CTAP_rpId *rp_id) {
	SHA256_CTX sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, rp_id->id, rp_id->id_size);
	sha256_final(&sha256_ctx, auth_data->fixed_header.rpIdHash);
}

typedef struct ctap_credentials_map_key {
	bool used;
	CTAP_rpId rpId;
	CTAP_userHandle userHandle;
} ctap_credentials_map_key;

typedef struct ctap_credentials_map_value {
	bool discoverable;
	uint32_t signCount;
	uint8_t id[128];
	// credProtect extension
	uint8_t credProtect;
	// the actual private key
	uint8_t private_key[32];
	// hmac-secret extension
	uint8_t CredRandomWithUV[32];
	uint8_t CredRandomWithoutUV[32];
} ctap_credentials_map_value;

static uint8_t create_attested_credential_data(
	CTAP_authenticator_data_attestedCredentialData *attested_credential_data,
	size_t *attested_credential_data_size,
	const uint8_t *public_key,
	const ctap_credentials_map_value *credential
) {

	static_assert(
		sizeof(attested_credential_data->fixed_header.aaguid) == sizeof(ctap_aaguid),
		"aaguid size mismatch"
	);

	memcpy(attested_credential_data->fixed_header.aaguid, ctap_aaguid, sizeof(ctap_aaguid));

	static_assert(sizeof(credential->id) <= 1023, "credentialIdLength MUST be <= 1023");
	attested_credential_data->fixed_header.credentialIdLength = lion_htons(sizeof(credential->id));

	memcpy(attested_credential_data->variable_data, credential->id, sizeof(credential->id));

	CborEncoder encoder;
	uint8_t ret;

	uint8_t *credentialPublicKey = &attested_credential_data->variable_data[sizeof(credential->id)];
	const size_t credentialPublicKey_buffer_size =
		sizeof(attested_credential_data->variable_data) - sizeof(credential->id);

	cbor_encoder_init(&encoder, credentialPublicKey, credentialPublicKey_buffer_size, 0);

	ctap_parse_check(encode_public_key(&encoder, public_key));

	*attested_credential_data_size =
		sizeof(attested_credential_data->fixed_header)
		+ sizeof(credential->id)
		+ cbor_encoder_get_buffer_size(&encoder, credentialPublicKey);

	assert(*attested_credential_data_size <= sizeof(CTAP_authenticator_data_attestedCredentialData));

	return CTAP2_OK;

}

static uint8_t encode_authenticator_data_extensions(
	uint8_t *buffer,
	const size_t buffer_size,
	size_t *extensions_size,
	const uint8_t extensions_present,
	const ctap_credentials_map_value *credential
) {

	CborEncoder encoder;
	cbor_encoder_init(&encoder, buffer, buffer_size, 0);

	CborError err;
	CborEncoder map;

	size_t num_extensions_in_output_map = 0;
	if ((extensions_present & CTAP_extension_credProtect) != 0u) {
		num_extensions_in_output_map++;
	}
	if ((extensions_present & CTAP_extension_hmac_secret) != 0u) {
		num_extensions_in_output_map++;
	}

	cbor_encoding_check(cbor_encoder_create_map(&encoder, &map, num_extensions_in_output_map));
	if ((extensions_present & CTAP_extension_credProtect) != 0u) {
		cbor_encoding_check(cbor_encode_text_string(&map, "credProtect", 11));
		cbor_encoding_check(cbor_encode_uint(&map, credential->credProtect));
	}
	if ((extensions_present & CTAP_extension_hmac_secret) != 0u) {
		cbor_encoding_check(cbor_encode_text_string(&map, "hmac-secret", 11));
		cbor_encoding_check(cbor_encode_boolean(&map, true));
	}
	cbor_encoding_check(cbor_encoder_close_container(&encoder, &map));

	*extensions_size = cbor_encoder_get_buffer_size(&encoder, buffer);

	return CTAP2_OK;

}

static uint8_t create_self_attestation_statement(
	CborEncoder *encoder,
	const CTAP_authenticator_data *auth_data,
	const size_t auth_data_size,
	const uint8_t *client_data_hash,
	const ctap_credentials_map_value *credential
) {

	// message_hash = SHA256(authenticatorData || clientDataHash)
	uint8_t message_hash[32];
	SHA256_CTX sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (const uint8_t *) auth_data, auth_data_size);
	sha256_update(&sha256_ctx, client_data_hash, 32);
	sha256_final(&sha256_ctx, message_hash);

	uint8_t signature[64];
	if (uECC_sign(
		credential->private_key,
		message_hash,
		sizeof(message_hash),
		signature,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_sign failed" nl);
		return CTAP1_ERR_OTHER;
	}

	// WebAuthn 6.5.5. Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types
	// For COSEAlgorithmIdentifier -7 (ES256), and other ECDSA-based algorithms,
	// the sig value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3.
	uint8_t asn1_der_sig[72];
	size_t asn1_der_sig_size;
	ctap_convert_to_asn1_der_ecdsa_sig_value(
		signature,
		asn1_der_sig,
		&asn1_der_sig_size
	);

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));
	// alg: COSEAlgorithmIdentifier
	cbor_encoding_check(cbor_encode_text_string(&map, "alg", 3));
	cbor_encoding_check(cbor_encode_int(&map, COSE_ALG_ES256));
	// sig: bytes
	cbor_encoding_check(cbor_encode_text_string(&map, "sig", 3));
	cbor_encoding_check(cbor_encode_byte_string(
		&map,
		asn1_der_sig,
		asn1_der_sig_size
	));
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

#define CTAP_MEMORY_MAX_NUM_CREDENTIALS 10
static ctap_credentials_map_key credentials_map_keys[CTAP_MEMORY_MAX_NUM_CREDENTIALS];
static ctap_credentials_map_value credentials_map_values[CTAP_MEMORY_MAX_NUM_CREDENTIALS];

static int find_credential_index(const CTAP_rpId *rp_id, const CTAP_userHandle *user_handle) {

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
		ctap_credentials_map_key *key = &credentials_map_keys[i];
		if (!key->used) {
			continue;
		}
		if (!ctap_rp_id_matches(&key->rpId, rp_id)) {
			continue;
		}
		if (!ctap_user_handle_matches(&key->userHandle, user_handle)) {
			continue;
		}
		return i;
	}

	return -1;

}

static uint8_t store_credential(
	const CTAP_rpId *rp_id,
	const CTAP_userHandle *user_handle,
	const ctap_credentials_map_value *credential
) {

	int slot;

	// If a credential for the same rpId and userHandle already exists on the authenticator,
	// then overwrite that credential.
	slot = find_credential_index(
		rp_id,
		user_handle
	);

	// Otherwise, find a free map slot and update the key.
	if (slot == -1) {
		for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
			ctap_credentials_map_key *key = &credentials_map_keys[i];
			if (!key->used) {
				slot = i;
				key->used = false;
				key->rpId = *rp_id;
				key->userHandle = *user_handle;
				break;
			}
		}
	}

	// No free space left.
	if (slot == -1) {
		return CTAP2_ERR_KEY_STORE_FULL;
	}

	ctap_credentials_map_value *value = &credentials_map_values[slot];
	value->discoverable = credential->discoverable;
	value->signCount = credential->signCount;
	memcpy(value->id, credential->id, sizeof(value->id));
	value->credProtect = credential->credProtect;
	memcpy(value->private_key, credential->private_key, sizeof(value->private_key));
	memcpy(value->CredRandomWithUV, credential->CredRandomWithUV, sizeof(value->CredRandomWithUV));
	memcpy(value->CredRandomWithoutUV, credential->CredRandomWithoutUV, sizeof(value->CredRandomWithoutUV));

	return CTAP2_OK;

}

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CborParser parser;
	CborValue it;
	ctap_parse_check(ctap_init_cbor_parser(request, length, &parser, &it));

	CTAP_makeCredential mc;
	ctap_parse_check(ctap_parse_make_credential(&it, &mc));

	const bool pinUvAuthParam_present = ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.1.2. authenticatorMakeCredential Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg
	// see also WebAuthn 6.3.2. The authenticatorMakeCredential Operation
	// https://w3c.github.io/webauthn/#sctn-op-make-cred

	// 1. If authenticator supports either pinUvAuthToken or clientPin features
	//    and the platform sends a zero length pinUvAuthParam:
	//    Note:
	//      This is done for backwards compatibility with CTAP2.0 platforms in the case
	//      where multiple authenticators are attached to the platform and the platform
	//      wants to enforce pinUvAuthToken feature semantics, but the user has to select
	//      which authenticator to get the pinUvAuthToken from.
	//      CTAP2.1 platforms SHOULD use 6.9 authenticatorSelection (0x0B).
	if (pinUvAuthParam_present && mc.pinUvAuthParam_size == 0) {
		// 1. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
		ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
		switch (up_result) {
			case CTAP_UP_RESULT_CANCEL:
				// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
				return CTAP2_ERR_KEEPALIVE_CANCEL;
			case CTAP_UP_RESULT_TIMEOUT:
			case CTAP_UP_RESULT_DENY:
				// 2. If the user declines permission, or the operation times out,
				//    then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
				return CTAP2_ERR_OPERATION_DENIED;
			case CTAP_UP_RESULT_ALLOW:
				// 3. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
				//    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
				return !state->persistent.is_pin_set ? CTAP2_ERR_PIN_NOT_SET : CTAP2_ERR_PIN_INVALID;
		}
	}

	// 2. If the pinUvAuthParam parameter is present:
	if (pinUvAuthParam_present) {
		// 2. If the pinUvAuthProtocol parameter is absent,
		//    return CTAP2_ERR_MISSING_PARAMETER error.
		if (!ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthProtocol)) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		// 1. If the pinUvAuthProtocol parameter's value is not supported,
		//    return CTAP1_ERR_INVALID_PARAMETER error.
		ctap_parse_check(ctap_get_pin_protocol(state, mc.pinUvAuthProtocol, &pin_protocol));
	}

	// 3. Validate pubKeyCredParams and choose the first supported algorithm.
	ctap_parse_check(ctap_parse_make_credential_pub_key_cred_params(&mc));
	debug_log("chosen algorithm = %" PRId32 nl, mc.pubKeyCredParams_chosen.alg);

	// 4. Create a new authenticatorMakeCredential response structure
	//    and initialize both its "uv" bit and "up" bit as false.
	CTAP_authenticator_data auth_data;
	memset(&auth_data, 0, sizeof(auth_data));
	// alls flags are initialized to 0 (false)

	const bool rk = get_option_value_or_false(&mc, CTAP_makeCredential_option_rk);
	debug_log("option rk=%d" nl, rk);
	// 5. If the options parameter is present, process all option keys and values present in the parameter.
	//    Treat any option keys that are not understood as absent.
	if (ctap_param_is_present(&mc, CTAP_makeCredential_options)) {
		// user verification:
		//   Note:
		//     Use of this "uv" option key is deprecated in CTAP2.1.
		//     Instead, platforms SHOULD create a pinUvAuthParam by obtaining pinUvAuthToken
		//     via getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions,
		//     as appropriate.
		//   Note:
		//     pinUvAuthParam and the "uv" option are processed as mutually exclusive
		//     with pinUvAuthParam taking precedence.
		const bool uv = pinUvAuthParam_present ? false : get_option_value_or_false(&mc, CTAP_makeCredential_option_uv);
		if (uv) {
			// 3. If the "uv" option is true then:
			//    1. If the authenticator does not support a built-in user verification method
			//       (as is the case with the current version of LionKey),
			//       end the operation by returning CTAP2_ERR_INVALID_OPTION.
			//       Note: One would expect the CTAP2_ERR_UNSUPPORTED_OPTION error code,
			//             but the spec really says CTAP2_ERR_INVALID_OPTION.
			return CTAP2_ERR_INVALID_OPTION;
		}
		// user presence (defaults to true):
		//   Instructs the authenticator to require user consent to complete the operation.
		//   Platforms MAY send the "up" option key to CTAP2.1 authenticators,
		//   and its value MUST be true if present.
		//   The value false will cause a CTAP2_ERR_INVALID_OPTION response regardless of authenticator version.
		if ((
			is_option_present(&mc, CTAP_makeCredential_option_up)
			&& get_option_value(&mc, CTAP_makeCredential_option_up) == false
		)) {
			return CTAP2_ERR_INVALID_OPTION;
		}
	}

	// 6. (not applicable to LionKey) If the alwaysUv option ID is present and true then ...

	// 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
	//    Note:
	//      This step returns an error if the platform tries to create a discoverable credential
	//      without performing some form of user verification.
	if (state->persistent.is_pin_set && !pinUvAuthParam_present && rk) {
		return CTAP2_ERR_PUAT_REQUIRED;
	}

	// 8. (not applicable to LionKey) Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response
	//    is present with the value false or is absent): ...

	// 9. If the enterpriseAttestation parameter is present:
	if (ctap_param_is_present(&mc, CTAP_makeCredential_enterpriseAttestation)) {
		// 1. If the authenticator is not enterprise attestation capable,
		//    or the authenticator is enterprise attestation capable but enterprise attestation is disabled,
		//    then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 10. Allow the authenticator to create a non-discoverable credential
	//     without requiring some form of user verification under the below specific criteria.
	const bool allow_no_verification = !rk && !pinUvAuthParam_present;
	debug_log("allow_no_verification=%d" nl, allow_no_verification);
	// 11. If the authenticator is protected by some form of user verification , then:
	if (!allow_no_verification && state->persistent.is_pin_set) {
		// 1. If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
		if (pinUvAuthParam_present) {
			// This should be ensured by Step 2.
			assert(pin_protocol != NULL);
			// 1. Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
			//    1. If the verification returns error,
			//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
			ctap_parse_check(verify(state, &mc, pin_protocol));
			// 2. Verify that the pinUvAuthToken has the mc permission,
			//    if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
			if (!ctap_pin_uv_auth_token_has_permissions(
				&state->pin_uv_auth_token_state,
				CTAP_clientPIN_pinUvAuthToken_permission_mc
			)) {
				return CTAP2_ERR_PIN_AUTH_INVALID;
			}
			// 3. If the pinUvAuthToken has a permissions RP ID associated:
			//    1. If the permissions RP ID does NOT match the rp.id in this request,
			//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
			if ((
				state->pin_uv_auth_token_state.rpId_set
				&& !ctap_rp_id_matches(&state->pin_uv_auth_token_state.rpId, &mc.rpId)
			)) {
				return CTAP2_ERR_PIN_AUTH_INVALID;
			}
			// TODO: Implement userVerifiedFlagValue handling in steps 4, 5, 6.
			// 7. If the pinUvAuthToken does not have a permissions RP ID associated:
			//    1. Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
			if (!state->pin_uv_auth_token_state.rpId_set) {
				state->pin_uv_auth_token_state.rpId = mc.rpId;
				state->pin_uv_auth_token_state.rpId_set = true;
			}
		}
		// 2. If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
		//    and that the authenticator supports an enabled built-in user verification method, see Step 5):
		//    (not applicable to LionKey)
	}

	// TODO: 12. If the excludeList parameter is present and contains a credential ID
	//           created by this authenticator, that is bound to the specified rp.id: ...

	// 13. (not applicable to LionKey) If evidence of user interaction was provided as part of Step 11
	//     (i.e., by invoking performBuiltInUv()): ...

	// 14. If the "up" option is set to true:
	//     Note: Step 3 ensures that the "up" option is effectively always true.
	// 14.1. and 14.2. together (since we do not perform step 13, the "up" bit in the response
	// can never be true at this point and thus the 14.2.1. check is unnecessary).
	const bool user_present = pinUvAuthParam_present && ctap_pin_uv_auth_token_get_user_present_flag_value(
		&state->pin_uv_auth_token_state
	);
	if (!user_present) {
		// 1. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
		//    If the authenticator has a display, show the items contained within the user and rp parameter
		//    structures to the user, and request permission to create a credential.
		ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
		switch (up_result) {
			case CTAP_UP_RESULT_CANCEL:
				// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
				return CTAP2_ERR_KEEPALIVE_CANCEL;
			case CTAP_UP_RESULT_TIMEOUT:
			case CTAP_UP_RESULT_DENY:
				// 2. If the user declines permission, or the operation times out,
				//    then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
				return CTAP2_ERR_OPERATION_DENIED;
			case CTAP_UP_RESULT_ALLOW:
				// continue
				break;
		}
	}
	// 14.3. Set the "up" bit to true in the response.
	auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_up;
	// 14.4. Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
	//       Note: This consumes both the "user present state", sometimes referred to as the "cached UP",
	//       and the "user verified state", sometimes referred to as "cached UV".
	//       These functions are no-ops if there is not an in-use pinUvAuthToken.
	ctap_pin_uv_auth_token_clear_user_present_flag(&state->pin_uv_auth_token_state);
	ctap_pin_uv_auth_token_clear_user_verified_flag(&state->pin_uv_auth_token_state);
	ctap_pin_uv_auth_token_clear_permissions_except_lbw(&state->pin_uv_auth_token_state);

	// extensions processing

	ctap_credentials_map_value credential;
	credential.discoverable = rk;
	credential.signCount = 1;

	// 12.1. Credential Protection (credProtect)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension
	//   credProtect value is persisted with the credential.
	//   If no credProtect extension was included in the request the authenticator
	//   SHOULD use the default value of 1 for compatibility with CTAP2.0 platforms.
	//   The authenticator MUST NOT return an unsolicited credProtect extension output.
	credential.credProtect = CTAP_extension_credProtect_1_userVerificationOptional;

	// 12.5. HMAC Secret Extension (hmac-secret)
	//   authenticatorMakeCredential additional behaviors
	//     The authenticator generates two random 32-byte values (called CredRandomWithUV and CredRandomWithoutUV)
	//     and associates them with the credential.
	//     Note:
	//       Authenticator SHOULD generate CredRandomWithUV/CredRandomWithoutUV and associate
	//       them with the credential, even if hmac-secret extension is NOT present
	//       in authenticatorMakeCredential request.
	ctap_generate_rng(credential.CredRandomWithUV, sizeof(credential.CredRandomWithUV));
	ctap_generate_rng(credential.CredRandomWithoutUV, sizeof(credential.CredRandomWithoutUV));

	// 15. If the extensions parameter is present:
	if (ctap_param_is_present(&mc, CTAP_makeCredential_extensions)) {
		// 1. Process any extensions that this authenticator supports,
		//    ignoring any that it does not support.
		// 2. Authenticator extension outputs generated by the authenticator
		//    extension processing are returned in the authenticator data.
		//    The set of keys in the authenticator extension outputs map MUST
		//    be equal to, or a subset of, the keys of the authenticator extension inputs map.
		// Note: Some extensions may produce different output depending on the state of
		// the "uv" bit and/or "up" bit in the response.
		if ((mc.extensions_present & CTAP_extension_credProtect) != 0u) {
			// Only set, if the given credProtect value is valid and non-default.
			// Note:
			//   The spec does not explicitly say what to do with invalid credProtect values.
			//   We decided to ignore any invalid values here since the actual used value will be returned
			//   in the response and the client/RP can decide, what to do.
			if ((
				mc.credProtect == CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList
				|| mc.credProtect == CTAP_extension_credProtect_3_userVerificationRequired
			)) {
				credential.credProtect = mc.credProtect;
			}
		}
	}

	// 16. Generate a new credential key pair for the algorithm chosen in step 3.
	// 17. If the "rk" option is set to true:
	//     1. The authenticator MUST create a discoverable credential.
	//     2. If a credential for the same rp.id and account ID already exists on the authenticator:
	//        1. If the existing credential contains a largeBlobKey, an authenticator MAY erase any
	//           associated large-blob data. Platforms MUST NOT assume that authenticators will do this.
	//           Platforms can later garbage collect any orphaned large-blobs.
	//        2. Overwrite that credential.
	//     3. Store the user parameter along with the newly-created key pair.
	//     4. If authenticator does not have enough internal storage to persist the new credential,
	//        return CTAP2_ERR_KEY_STORE_FULL.
	// 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
	//     Note: This step is a change from CTAP2.0 where if the "rk" option is false the authenticator
	//           could optionally create a discoverable credential.

	credential.id[0] = 0x01u; // version
	ctap_generate_rng(&credential.id[1], sizeof(credential.id) - 1);
	ctap_generate_rng(credential.private_key, sizeof(credential.private_key));
	uint8_t public_key[64];
	if (uECC_compute_public_key(
		credential.private_key,
		public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return CTAP1_ERR_OTHER;
	}
	ctap_parse_check(store_credential(&mc.rpId, &mc.user.id, &credential));

	// 19. Generate an attestation statement for the newly-created credential using clientDataHash,
	//     taking into account the value of the enterpriseAttestation parameter, if present,
	//     as described above in Step 9.

	auth_data_compute_rp_id_hash(&auth_data, &mc.rpId);
	auth_data.fixed_header.signCount = credential.signCount;

	size_t auth_data_variable_size = 0;
	const size_t auth_data_variable_max_size = sizeof(auth_data.variable_data);

	CTAP_authenticator_data_attestedCredentialData *attested_credential_data =
		(CTAP_authenticator_data_attestedCredentialData *) &auth_data.variable_data[auth_data_variable_size];
	size_t attested_credential_data_size;
	ctap_parse_check(create_attested_credential_data(
		attested_credential_data,
		&attested_credential_data_size,
		public_key,
		&credential
	));
	auth_data_variable_size += attested_credential_data_size;

	size_t extensions_size;
	ctap_parse_check(encode_authenticator_data_extensions(
		&auth_data.variable_data[auth_data_variable_size],
		auth_data_variable_max_size - auth_data_variable_size,
		&extensions_size,
		mc.extensions_present,
		&credential
	));
	auth_data_variable_size += extensions_size;

	assert(auth_data_variable_size < auth_data_variable_max_size);

	const size_t auth_data_total_size = sizeof(auth_data.fixed_header) + auth_data_variable_size;

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 3));
	// fmt (0x01)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_makeCredential_res_fmt));
	cbor_encoding_check(cbor_encode_text_string(&map, "packed", 6));
	// authData (0x02)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_makeCredential_res_authData));
	cbor_encoding_check(cbor_encode_byte_string(
		&map,
		(const uint8_t *) &auth_data,
		auth_data_total_size
	));
	// attStmt (0x03)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_makeCredential_res_attStmt));
	ctap_parse_check(create_self_attestation_statement(
		&map,
		&auth_data,
		auth_data_total_size,
		mc.clientDataHash,
		&credential
	));
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

// https://w3c.github.io/webauthn/#credential-id
// Credential ID
//
// A probabilistically-unique byte sequence identifying a public key credential source
// and its authentication assertions. At most 1023 bytes long.
//
// Credential IDs are generated by authenticators in two forms:
//
//   1. At least 16 bytes that include at least 100 (~ 13 bytes) bits of entropy, or
//
//   2. The public key credential source, without its Credential ID or mutable items,
//      encrypted so only its managing authenticator can decrypt it.
//      This form allows the authenticator to be nearly stateless,
//      by having the Relying Party store any necessary state.
//
//   Note: [FIDO-UAF-AUTHNR-CMDS] includes guidance on encryption techniques under "Security Guidelines".
//     https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-authnr-cmds-v1.1-id-20170202.html#security-guidelines:~:text=regarding%20random%20numbers-,KeyHandle,-It%20is%20highly
//       It is highly recommended to use authenticated encryption while wrapping key handles with Wrap.sym.
//       Algorithms such as AES-GCM and AES-CCM are most suitable for this operation.
//     https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-authnr-cmds-v1.1-id-20170202.html#security-guidelines:~:text=the%20authenticator%20together.-,Wrap.sym,-If%20the%20authenticator
//        Refer to [SP800-57] and [SP800-38F] publications for more information
//        about choosing the right wrapping algorithm and implementing it correctly.
//
//   Relying Parties do not need to distinguish these two Credential ID forms.
//

// Each authenticator stores a credentials map, a map from (rpId, userHandle) to public key credential source.

// a301667061636b65640259011274a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef001010000000076631bd4a0427f57730ec71c9e02790080015c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77c78abf7d00c51fc7184418ec5f66f19c6ac0d8304d4f3a10c0d67b61782ce205d72c84c9aad82d2db1a0e254a3cd060163136f108944960e4defc264f2b4479ea50102032620012158207ebf02ddcab6a9675a6a9fc5c22edac98f954e9c0b730668314c65fbe58afbb8225820d42fbc2f7f34580caf1d53b96043a73ef4636476814e6874efe986a30d3c3fb1a16b6372656450726f746563740203a263616c67266373696758473045022100f33cbf04ca246a131f99bfcfb4a85e9b242e9e228a088237e7e7570363a918e8022069bd060566a828790b3927311f0fed6ba1f58014e3a725e10fa8d8750c042f2a
//
// a301667061636b65640259011274a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef001010000000076631bd4a0427f57730ec71c9e0279008001 bdc5d72b200b68d48ab6eba57d9c6fe8021bd3d9973533ae94b51d43232789492997832edab26c031f098a1badc7a73d55612c22a2582185e8ff2400cb22c57eb5fe50be88bd81d17023785ba87424b0194367fc23721e1df1219211dd54fd0245658c2c75fd426f5b55a727cb969e91c6c7125c2b53b1295dae95c959f2e0a5010203262001215820a55c929dabd8694e117bc5b42a508b68b2368679af6d9c990aac3f6361c5b393225820eb8304f47a706f151e504cdad712e034787f94e31c13d6caca3d8ac36d13d839a16b6372656450726f746563740203a263616c6726637369675846304402201f52efe198918cbd6f25dbaff9a91b255aa86bc14b93e6e34e5a48fe6520eac902201ad34c20f6fb2d3aac5a5d055522f929175b9f48998d3b013730ec7b19fba6b8
