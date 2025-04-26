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

static inline bool is_option_present(const CTAP_mc_ga_options *options, const uint8_t option) {
	return (options->present & option) == option;
}

static inline bool get_option_value(const CTAP_mc_ga_options *options, const uint8_t option) {
	return (options->values & option) == option;
}

static inline bool get_option_value_or_false(const CTAP_mc_ga_options *options, const uint8_t option) {
	return is_option_present(options, option) ? get_option_value(options, option) : false;
}

static inline bool get_option_value_or_true(const CTAP_mc_ga_options *options, const uint8_t option) {
	return is_option_present(options, option) ? get_option_value(options, option) : true;
}

static inline uint8_t verify(
	ctap_state_t *state,
	const CTAP_mc_ga_common *params,
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
		/* message */ params->clientDataHash, sizeof(params->clientDataHash)
	);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ params->pinUvAuthParam, params->pinUvAuthParam_size
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

static uint8_t encode_pub_key_cred_desc(
	CborEncoder *encoder,
	const size_t cred_id_size,
	const uint8_t *cred_id_data
) {

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));

	cbor_encoding_check(cbor_encode_text_string(&map, "id", 2));
	cbor_encoding_check(cbor_encode_byte_string(&map, cred_id_data, cred_id_size));

	cbor_encoding_check(cbor_encode_text_string(&map, "type", 4));
	cbor_encoding_check(cbor_encode_text_string(&map, "public-key", 10));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t encode_pub_key_cred_user_entity(
	CborEncoder *encoder,
	const CTAP_userEntity *user
) {

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(
		encoder,
		&map,
		user->displayName_present ? 2 : 1)
	);

	cbor_encoding_check(cbor_encode_text_string(&map, "id", 2));
	cbor_encoding_check(cbor_encode_byte_string(&map, user->id.id, user->id.id_size));

	if (user->displayName_present) {
		cbor_encoding_check(cbor_encode_text_string(&map, "displayName", 11));
		cbor_encoding_check(cbor_encode_text_string(&map, (const char *) user->displayName, user->displayName_size));
	}

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
	CTAP_userEntity user;
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

	ctap_check(encode_public_key(&encoder, public_key));

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

static uint8_t compute_signature(
	const CTAP_authenticator_data *auth_data,
	const size_t auth_data_size,
	const uint8_t *client_data_hash,
	const ctap_credentials_map_value *credential,
	uint8_t asn1_der_sig[72],
	size_t *asn1_der_sig_size
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
	ctap_convert_to_asn1_der_ecdsa_sig_value(
		signature,
		asn1_der_sig,
		asn1_der_sig_size
	);

	return CTAP2_OK;

}

static uint8_t create_self_attestation_statement(
	CborEncoder *encoder,
	const CTAP_authenticator_data *auth_data,
	const size_t auth_data_size,
	const uint8_t *client_data_hash,
	const ctap_credentials_map_value *credential
) {

	uint8_t ret;

	uint8_t asn1_der_sig[72];
	size_t asn1_der_sig_size;
	ctap_check(compute_signature(
		auth_data,
		auth_data_size,
		client_data_hash,
		credential,
		asn1_der_sig,
		&asn1_der_sig_size
	));

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
		if (!ctap_user_handle_matches(&key->user.id, user_handle)) {
			continue;
		}
		return i;
	}

	return -1;

}

static int lookup_credential_by_desc(const CTAP_credDesc *cred_desc) {

	if (cred_desc->type != CTAP_pubKeyCredType_public_key || cred_desc->id.size != 128) {
		return -1;
	}

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
		ctap_credentials_map_key *key = &credentials_map_keys[i];
		if (!key->used) {
			continue;
		}
		ctap_credentials_map_value *value = &credentials_map_values[i];
		static_assert(sizeof(value->id) == 128, "sizeof(value->id) == 128");
		if (memcmp(cred_desc->id.data, value->id, 128) == 0) {
			return i;
		}
	}

	return -1;

}

static uint8_t store_credential(
	const CTAP_rpId *rp_id,
	const CTAP_userEntity *user,
	const ctap_credentials_map_value *credential
) {

	int slot;

	// If a credential for the same rpId and userHandle already exists on the authenticator,
	// then overwrite that credential.
	slot = find_credential_index(
		rp_id,
		&user->id
	);

	// Otherwise, find a free map slot and update the key.
	if (slot == -1) {
		for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
			ctap_credentials_map_key *key = &credentials_map_keys[i];
			if (!key->used) {
				slot = i;
				key->used = true;
				key->rpId = *rp_id;
				key->user = *user;
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

void ctap_reset_credentials_store(void) {
	memset(credentials_map_keys, 0, sizeof(credentials_map_keys));
	memset(credentials_map_values, 0, sizeof(credentials_map_values));
}

/**
 * This functions implements Step 1 (handling of the legacy CTAP2.0 selection behavior)
 * and Step 2 (validating pinUvAuthProtocol and getting the pointer to the corresponding ctap_pin_protocol_t).
 *
 * These steps are common to both 6.1.2. authenticatorMakeCredential Algorithm
 * and 6.2.2. authenticatorGetAssertion Algorithm.
 *
 * @return CTAP2_OK if the caller function should continue with the request processing,
 *         otherwise the caller function should stop processing the request and return the error code
 */
static uint8_t handle_pin_uv_auth_param_and_protocol(
	ctap_state_t *state,
	const bool pinUvAuthParam_present,
	const size_t pinUvAuthParam_size,
	const bool pinUvAuthProtocol_present,
	const uint8_t pinUvAuthProtocol,
	ctap_pin_protocol_t **pin_protocol
) {
	uint8_t ret;

	// 1. If authenticator supports either pinUvAuthToken or clientPin features
	//    and the platform sends a zero length pinUvAuthParam:
	//    Note:
	//      This is done for backwards compatibility with CTAP2.0 platforms in the case
	//      where multiple authenticators are attached to the platform and the platform
	//      wants to enforce pinUvAuthToken feature semantics, but the user has to select
	//      which authenticator to get the pinUvAuthToken from.
	//      CTAP2.1 platforms SHOULD use 6.9 authenticatorSelection (0x0B).
	if (pinUvAuthParam_present && pinUvAuthParam_size == 0) {
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
		if (!pinUvAuthProtocol_present) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		// 1. If the pinUvAuthProtocol parameter's value is not supported,
		//    return CTAP1_ERR_INVALID_PARAMETER error.
		ctap_check(ctap_get_pin_protocol(state, pinUvAuthProtocol, pin_protocol));
	}

	// the caller function should continue with the request processing
	return CTAP2_OK;
}

/**
 * Ensures that the effective value of the "uv" option is false.
 *
 * Currently, LionKey does not support a built-in user verification method,
 * therefore the only supported "uv" option value is false.
 * Note that "clientPin" is NOT a "built-in user verification method",
 * it is only considered to be "some form of user verification".
 *
 * @param pinUvAuthParam_present If the pinUvAuthParam is present, the "uv" option is ignored.
 * @param options
 *
 * @return CTAP2_OK if the effective value of the "uv" option is false
 */
static uint8_t ensure_uv_option_false(const bool pinUvAuthParam_present, CTAP_mc_ga_options *options) {
	// user verification:
	//   Note:
	//     Use of this "uv" option key is deprecated in CTAP2.1.
	//     Instead, platforms SHOULD create a pinUvAuthParam by obtaining pinUvAuthToken
	//     via getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions,
	//     as appropriate.
	//   Note:
	//     pinUvAuthParam and the "uv" option are processed as mutually exclusive
	//     with pinUvAuthParam taking precedence.
	const bool uv = pinUvAuthParam_present ? false : get_option_value_or_false(options, CTAP_ma_ga_option_uv);
	if (uv) {
		// 3. If the "uv" option is true then:
		//    1. If the authenticator does not support a built-in user verification method
		//       (as is the case with the current version of LionKey),
		//       end the operation by returning CTAP2_ERR_INVALID_OPTION.
		//       Note: One would expect the CTAP2_ERR_UNSUPPORTED_OPTION error code,
		//             but the spec really says CTAP2_ERR_INVALID_OPTION.
		debug_log(red("unsupported uv option value true") nl);
		return CTAP2_ERR_INVALID_OPTION;
	}
	return CTAP2_OK;
}

static uint8_t ensure_valid_pin_uv_auth_param(
	ctap_state_t *state,
	CTAP_mc_ga_common *params,
	ctap_pin_protocol_t *pin_protocol,
	uint32_t permissions
) {
	uint8_t ret;
	// 1. Call verify(key=pinUvAuthToken, message=clientDataHash, signature: pinUvAuthParam).
	//    1. If the verification returns error,
	//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
	ctap_check(verify(state, params, pin_protocol));
	// 2. Verify that the pinUvAuthToken has the mc permission,
	//    if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if (!ctap_pin_uv_auth_token_has_permissions(
		&state->pin_uv_auth_token_state,
		permissions
	)) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// 3. If the pinUvAuthToken has a permissions RP ID associated:
	//    1. If the permissions RP ID does NOT match the rp.id in this request,
	//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if ((
		state->pin_uv_auth_token_state.rpId_set
		&& !ctap_rp_id_matches(&state->pin_uv_auth_token_state.rpId, &params->rpId)
	)) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
	// If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if (!ctap_pin_uv_auth_token_get_user_verified_flag_value(&state->pin_uv_auth_token_state)) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// If the pinUvAuthToken does not have a permissions RP ID associated:
	// Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
	if (!state->pin_uv_auth_token_state.rpId_set) {
		state->pin_uv_auth_token_state.rpId = params->rpId;
		state->pin_uv_auth_token_state.rpId_set = true;
	}
	return CTAP2_OK;
}

static uint8_t ensure_user_present(ctap_state_t *state, const bool pinUvAuthParam_present) {
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
				ctap_send_keepalive_if_needed(CTAP_STATUS_PROCESSING);
				break;
		}
	}
	return CTAP2_OK;
}

static uint8_t process_exclude_list(
	ctap_state_t *state,
	const CborValue *excludeList,
	const CTAP_rpId *rpId,
	const bool pinUvAuthParam_present,
	const bool uv_collected
) {
	uint8_t ret;

	ctap_parse_pub_key_cred_desc_list_ctx list_ctx;
	ctap_check(ctap_parse_pub_key_cred_desc_list_init(&list_ctx, excludeList));

	CTAP_credDesc *cred_desc;
	while (true) {
		ctap_check(ctap_parse_pub_key_cred_desc_list_next_cred(&list_ctx, &cred_desc));
		// if the end of the list, stop iteration
		if (cred_desc == NULL) {
			break;
		}
		int idx = lookup_credential_by_desc(cred_desc);
		if (idx == -1) {
			debug_log("process_exclude_list: skipping unknown credential ID" nl);
			continue;
		}
		if (!ctap_rp_id_matches(rpId, &credentials_map_keys[idx].rpId)) {
			debug_log("process_exclude_list: skipping credential ID that is bound to a different RP" nl);
			continue;
		}
		ctap_credentials_map_value *cred = &credentials_map_values[idx];
		if (cred->credProtect == CTAP_extension_credProtect_3_userVerificationRequired && !uv_collected) {
			debug_log(
				"process_exclude_list:"
				" skipping a credential with credProtect_3_userVerificationRequired"
				" because uv not collected" nl
			);
			continue;
		}
		// TODO:
		//   What is the pinUvAuthParam is invalid?
		//   Note that it is validated only if !allow_no_verification && state->persistent.is_pin_set (see Step 11).
		const bool user_present = pinUvAuthParam_present && ctap_pin_uv_auth_token_get_user_present_flag_value(
			&state->pin_uv_auth_token_state
		);
		if (!user_present) {
			debug_log("process_exclude_list: collecting user presence ..." nl);
			ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
			if (up_result == CTAP_UP_RESULT_CANCEL) {
				// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
				return CTAP2_ERR_KEEPALIVE_CANCEL;
			}
		}
		return CTAP2_ERR_CREDENTIAL_EXCLUDED;
	}

	return CTAP2_OK;
}

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CborParser parser;
	CborValue it;
	ctap_check(ctap_init_cbor_parser(request, length, &parser, &it));

	CTAP_makeCredential mc;
	CTAP_mc_ga_common *const params = &mc.common;
	ctap_check(ctap_parse_make_credential(&it, &mc));

	const bool pinUvAuthParam_present = ctap_param_is_present(params, CTAP_makeCredential_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.1.2. authenticatorMakeCredential Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg
	// see also WebAuthn 6.3.2. The authenticatorMakeCredential Operation
	// https://w3c.github.io/webauthn/#sctn-op-make-cred

	// 1. + 2.
	ctap_check(handle_pin_uv_auth_param_and_protocol(
		state,
		pinUvAuthParam_present,
		params->pinUvAuthParam_size,
		ctap_param_is_present(params, CTAP_makeCredential_pinUvAuthProtocol),
		params->pinUvAuthProtocol,
		&pin_protocol
	));

	// 3. Validate pubKeyCredParams and choose the first supported algorithm.
	ctap_check(ctap_parse_make_credential_pub_key_cred_params(&mc));
	debug_log("chosen algorithm = %" PRId32 nl, mc.pubKeyCredParams_chosen.alg);

	// 4. Create a new authenticatorMakeCredential response structure
	//    and initialize both its "uv" bit and "up" bit as false.
	CTAP_authenticator_data auth_data;
	memset(&auth_data, 0, sizeof(auth_data));
	// thanks to the memset above, alls flags are initialized to 0 (false)

	// 5. If the options parameter is present, process all option keys and values present in the parameter.
	//    Treat any option keys that are not understood as absent.
	const bool rk = get_option_value_or_false(&params->options, CTAP_ma_ga_option_rk);
	debug_log("option rk=%d" nl, rk);
	if (ctap_param_is_present(params, CTAP_makeCredential_options)) {
		ctap_check(ensure_uv_option_false(pinUvAuthParam_present, &params->options));
		// user presence (defaults to true):
		//   Instructs the authenticator to require user consent to complete the operation.
		//   Platforms MAY send the "up" option key to CTAP2.1 authenticators,
		//   and its value MUST be true if present.
		//   The value false will cause a CTAP2_ERR_INVALID_OPTION response regardless of authenticator version.
		if ((
			is_option_present(&params->options, CTAP_ma_ga_option_up)
			&& get_option_value(&params->options, CTAP_ma_ga_option_up) == false
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
	if (ctap_param_is_present(params, CTAP_makeCredential_enterpriseAttestation)) {
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
			assert(pin_protocol != NULL); // <- this should be ensured by Step 2
			ctap_check(ensure_valid_pin_uv_auth_param(
				state,
				params,
				pin_protocol,
				CTAP_clientPIN_pinUvAuthToken_permission_mc
			));
			auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_uv;
		}
		// 2. If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
		//    and that the authenticator supports an enabled built-in user verification method, see Step 5):
		//    (not applicable to LionKey)
	}

	// 12. If the excludeList parameter is present ...
	if (ctap_param_is_present(params, CTAP_makeCredential_excludeList)) {
		ctap_check(process_exclude_list(
			state,
			&mc.excludeList,
			&params->rpId,
			pinUvAuthParam_present,
			(auth_data.fixed_header.flags & CTAP_authenticator_data_flags_uv) != 0u
		));
	}

	// 13. (not applicable to LionKey) If evidence of user interaction was provided as part of Step 11
	//     (i.e., by invoking performBuiltInUv()): ...

	// 14. If the "up" option is set to true:
	//     Note: Step 3 ensures that the "up" option is effectively always true.
	// 14.1. and 14.2. together (since we do not perform Step 13, the "up" bit in the response
	// can never be true at this point and thus the 14.2.1. check is unnecessary).
	ctap_check(ensure_user_present(state, pinUvAuthParam_present));
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
	if (ctap_param_is_present(params, CTAP_makeCredential_extensions)) {
		// 1. Process any extensions that this authenticator supports,
		//    ignoring any that it does not support.
		// 2. Authenticator extension outputs generated by the authenticator
		//    extension processing are returned in the authenticator data.
		//    The set of keys in the authenticator extension outputs map MUST
		//    be equal to, or a subset of, the keys of the authenticator extension inputs map.
		// Note: Some extensions may produce different output depending on the state of
		// the "uv" bit and/or "up" bit in the response.
		if ((params->extensions_present & CTAP_extension_credProtect) != 0u) {
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

	// 16. Generate a new credential key pair for the algorithm chosen in Step 3.
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
	ctap_check(store_credential(&params->rpId, &mc.user, &credential));

	// 19. Generate an attestation statement for the newly-created credential using clientDataHash,
	//     taking into account the value of the enterpriseAttestation parameter, if present,
	//     as described above in Step 9.

	auth_data_compute_rp_id_hash(&auth_data, &params->rpId);
	auth_data.fixed_header.signCount = lion_htonl(credential.signCount);

	size_t auth_data_variable_size = 0;
	const size_t auth_data_variable_max_size = sizeof(auth_data.variable_data);

	CTAP_authenticator_data_attestedCredentialData *attested_credential_data =
		(CTAP_authenticator_data_attestedCredentialData *) &auth_data.variable_data[auth_data_variable_size];
	size_t attested_credential_data_size;
	ctap_check(create_attested_credential_data(
		attested_credential_data,
		&attested_credential_data_size,
		public_key,
		&credential
	));
	auth_data_variable_size += attested_credential_data_size;
	auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_at;

	if (ctap_param_is_present(params, CTAP_makeCredential_extensions)) {
		size_t extensions_size;
		ctap_check(encode_authenticator_data_extensions(
			&auth_data.variable_data[auth_data_variable_size],
			auth_data_variable_max_size - auth_data_variable_size,
			&extensions_size,
			params->extensions_present,
			&credential
		));
		auth_data_variable_size += extensions_size;
		auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_ed;
	}

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
	ctap_check(create_self_attestation_statement(
		&map,
		&auth_data,
		auth_data_total_size,
		params->clientDataHash,
		&credential
	));
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

uint8_t ctap_get_assertion(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CborParser parser;
	CborValue it;
	ctap_check(ctap_init_cbor_parser(request, length, &parser, &it));

	CTAP_getAssertion ga;
	CTAP_mc_ga_common *const params = &ga.common;
	ctap_check(ctap_parse_get_assertion(&it, &ga));

	const bool pinUvAuthParam_present = ctap_param_is_present(params, CTAP_makeCredential_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.2.2. authenticatorGetAssertion Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-getAssert-authnr-alg
	// see also WebAuthn 6.3.3. The authenticatorGetAssertion Operation
	// https://w3c.github.io/webauthn/#sctn-op-get-assertion

	// 1. + 2.
	ctap_check(handle_pin_uv_auth_param_and_protocol(
		state,
		pinUvAuthParam_present,
		params->pinUvAuthParam_size,
		ctap_param_is_present(params, CTAP_makeCredential_pinUvAuthProtocol),
		params->pinUvAuthProtocol,
		&pin_protocol
	));

	// 3. Create a new authenticatorGetAssertion response structure
	//    and initialize both its "uv" bit and "up" bit as false.
	CTAP_authenticator_data auth_data;
	memset(&auth_data, 0, sizeof(auth_data));
	// thanks to the memset above, alls flags are initialized to 0 (false)

	// 4. If the options parameter is present, process all option keys and values present in the parameter.
	//    Treat any option keys that are not understood as absent.
	// 4.5. If the "up" option is not present then, let the "up" option be treated
	//      as being present with the value true.
	const bool up = get_option_value_or_true(&params->options, CTAP_ma_ga_option_up);
	debug_log("option up=%d" nl, up);
	if (ctap_param_is_present(params, CTAP_makeCredential_options)) {
		// 1. +. 2. + 3.
		ctap_check(ensure_uv_option_false(pinUvAuthParam_present, &params->options));
		// 4. If the "rk" option is present then, return CTAP2_ERR_UNSUPPORTED_OPTION.
		if (is_option_present(&params->options, CTAP_ma_ga_option_rk)) {
			return CTAP2_ERR_UNSUPPORTED_OPTION;
		}
	}

	// 5. (not applicable to LionKey) If the alwaysUv option ID is present and true and ...

	// 6. If the authenticator is protected by some form of user verification , then:
	if (state->persistent.is_pin_set) {
		// 1. If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 4)):
		if (pinUvAuthParam_present) {
			assert(pin_protocol != NULL); // <- this should be ensured by Step 2
			ctap_check(ensure_valid_pin_uv_auth_param(
				state,
				params,
				pin_protocol,
				CTAP_clientPIN_pinUvAuthToken_permission_ga
			));
			auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_uv;
		}
		// 2. If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
		//    and that the authenticator supports an enabled built-in user verification method, see Step 4):
		//    (not applicable to LionKey)
	}

	// TODO: 7. Locate all credentials that are eligible for retrieval under the specified criteria:
	//
	//   1. If the allowList parameter is present and is non-empty,
	//      locate all denoted credentials created by this authenticator and bound to the specified rpId.
	//   2. If an allowList is not present, locate all discoverable credentials
	//      that are created by this authenticator and bound to the specified rpId.
	//   3. Create an applicable credentials list populated with the located credentials.
	//   4. Iterate through the applicable credentials list, and if credential protection for a credential
	//      is marked as userVerificationRequired, and the "uv" bit is false in the response,
	//      remove that credential from the applicable credentials list.
	//   5. Iterate through the applicable credentials list, and if credential protection for a credential
	//      is marked as userVerificationOptionalWithCredentialIDList and there is no allowList passed by
	//      the client and the "uv" bit is false in the response, remove that credential
	//      from the applicable credentials list.
	//   6. If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
	//   7. Let numberOfCredentials be the number of applicable credentials found.
	// TODO: This is just for a demo.
	ctap_credentials_map_key *credential_key = &credentials_map_keys[0];
	ctap_credentials_map_value *credential = &credentials_map_values[0];
	if (!credential_key->used) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	// 8. (not applicable to LionKey) If evidence of user interaction was provided as part of Step 6.2
	//    (i.e., by invoking performBuiltInUv()): ...

	// 9. If the "up" option is set to true or not present
	//    (not present has already been replaced with true, the default, in Step 4):
	if (up) {
		// 9.1. and 9.2. together (since we do not perform Step 8, the "up" bit in the response
		// can never be true at this point and thus the 9.2.1. check is unnecessary).
		ctap_check(ensure_user_present(state, pinUvAuthParam_present));
		// 9.3. Set the "up" bit to true in the response.
		auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_up;
		// 9.4. Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
		//      Note: This consumes both the "user present state", sometimes referred to as the "cached UP",
		//      and the "user verified state", sometimes referred to as "cached UV".
		//      These functions are no-ops if there is not an in-use pinUvAuthToken.
		ctap_pin_uv_auth_token_clear_user_present_flag(&state->pin_uv_auth_token_state);
		ctap_pin_uv_auth_token_clear_user_verified_flag(&state->pin_uv_auth_token_state);
		ctap_pin_uv_auth_token_clear_permissions_except_lbw(&state->pin_uv_auth_token_state);
	}

	// extensions processing

	// 10. If the extensions parameter is present:
	if (ctap_param_is_present(params, CTAP_makeCredential_extensions)) {
		// 1. Process any extensions that this authenticator supports,
		//    ignoring any that it does not support.
		// 2. Authenticator extension outputs generated by the authenticator
		//    extension processing are returned in the authenticator data.
		//    The set of keys in the authenticator extension outputs map MUST
		//    be equal to, or a subset of, the keys of the authenticator extension inputs map.
		// Note: Some extensions may produce different output depending on the state of
		// the "uv" bit and/or "up" bit in the response.
		if ((params->extensions_present & CTAP_extension_hmac_secret) != 0u) {
			// TODO
		}
	}

	// TODO: 11. If the allowList parameter is present: ...
	// TODO: 12. If allowList is not present: ...

	// 13. Sign the clientDataHash along with authData with the selected credential
	//     using the structure specified in

	uint8_t public_key[64];
	if (uECC_compute_public_key(
		credential->private_key,
		public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return CTAP1_ERR_OTHER;
	}

	auth_data_compute_rp_id_hash(&auth_data, &params->rpId);
	credential->signCount++;
	auth_data.fixed_header.signCount = lion_htonl(credential->signCount);

	size_t auth_data_variable_size = 0;
	const size_t auth_data_variable_max_size = sizeof(auth_data.variable_data);

	// if (ctap_param_is_present(params, CTAP_makeCredential_extensions)) {
	// 	size_t extensions_size;
	// 	ctap_check(encode_authenticator_data_extensions(
	// 		&auth_data.variable_data[auth_data_variable_size],
	// 		auth_data_variable_max_size - auth_data_variable_size,
	// 		&extensions_size,
	// 		params->extensions_present,
	// 		credential
	// 	));
	// 	auth_data_variable_size += extensions_size;
	// 	auth_data.fixed_header.flags |= CTAP_authenticator_data_flags_ed;
	// }

	assert(auth_data_variable_size < auth_data_variable_max_size);

	const size_t auth_data_total_size = sizeof(auth_data.fixed_header) + auth_data_variable_size;

	uint8_t asn1_der_sig[72];
	size_t asn1_der_sig_size;
	ctap_check(compute_signature(
		&auth_data,
		auth_data_total_size,
		params->clientDataHash,
		credential,
		asn1_der_sig,
		&asn1_der_sig_size
	));

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 4));
	// credential (0x01)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_credential));
	ctap_check(encode_pub_key_cred_desc(&map, sizeof(credential->id), credential->id));
	// authData (0x02)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_authData));
	cbor_encoding_check(cbor_encode_byte_string(
		&map,
		(const uint8_t *) &auth_data,
		auth_data_total_size
	));
	// signature (0x03)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_signature));
	cbor_encoding_check(cbor_encode_byte_string(
		&map,
		asn1_der_sig,
		asn1_der_sig_size
	));
	// user (0x04)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_user));
	ctap_check(encode_pub_key_cred_user_entity(&map, &credential_key->user));
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

// CTAP_CMD_MAKE_CREDENTIAL
// a901582089d9082641f278c8d14ff5dee5b37278c65828a35db2c655d8c5127d116af52a02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644f776562617574686e696f2d74657374646e616d6564746573746b646973706c61794e616d6564746573740483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b65790589a2626964582010fb4150582533443770b81a8de745264a83c1be657baffe19407984a5f7e49864747970656a7075626c69632d6b6579a2626964582017d916f7bfcc36c06560b33e9853667589aa02b5d2bacbfe30fbd839f884265564747970656a7075626c69632d6b6579a2626964505ddc39cdb0861519f62e8ea6d81261d264747970656a7075626c69632d6b6579a26269645079f44e7b425238648d7297ed7db33b6164747970656a7075626c69632d6b6579a262696458208cb4a9e133b344031275c53f09b4c1d7470a4428f108657d98b297f74ec51def64747970656a7075626c69632d6b6579a26269645820d6aabcad657fed771bfce38809ca8c3bef0f11008960485a7ba4f4f6cbb6d44764747970656a7075626c69632d6b6579a26269645820f3d3f9cc85b616c51d7b6c2c90cfda630033a6a0b7f6ab26725b2692bf31bfc064747970656a7075626c69632d6b6579a26269645820f5def8ab4ac260b1fdfc2c4d65e9b436f311b0c301de7dfe57080e558d8714cc64747970656a7075626c69632d6b6579a26269645820fe9703fa1d3e4997e15ddebf1588cd0b83d8efd85b4ca2e45f6f83a946f2acf564747970656a7075626c69632d6b657906a16b6372656450726f746563740207a162726bf508503a0bc8d0eab4f9c3362f9652f4e9da160901
// {
//     1: h'89d9082641f278c8d14ff5dee5b37278c65828a35db2c655d8c5127d116af52a',
//     2: {"id": "webauthn.io", "name": "webauthn.io"},
//     3: {
//         "id": h'776562617574686e696f2d74657374',
//         "name": "test",
//         "displayName": "test",
//     },
//     4: [
//         {"alg": -8, "type": "public-key"},
//         {"alg": -7, "type": "public-key"},
//         {"alg": -257_1, "type": "public-key"},
//     ],
//     5: [
//         {
//             "id": h'10fb4150582533443770b81a8de745264a83c1be657baffe19407984a5f7e498',
//             "type": "public-key",
//         },
//         {
//             "id": h'17d916f7bfcc36c06560b33e9853667589aa02b5d2bacbfe30fbd839f8842655',
//             "type": "public-key",
//         },
//         {
//             "id": h'5ddc39cdb0861519f62e8ea6d81261d2',
//             "type": "public-key",
//         },
//         {
//             "id": h'79f44e7b425238648d7297ed7db33b61',
//             "type": "public-key",
//         },
//         {
//             "id": h'8cb4a9e133b344031275c53f09b4c1d7470a4428f108657d98b297f74ec51def',
//             "type": "public-key",
//         },
//         {
//             "id": h'd6aabcad657fed771bfce38809ca8c3bef0f11008960485a7ba4f4f6cbb6d447',
//             "type": "public-key",
//         },
//         {
//             "id": h'f3d3f9cc85b616c51d7b6c2c90cfda630033a6a0b7f6ab26725b2692bf31bfc0',
//             "type": "public-key",
//         },
//         {
//             "id": h'f5def8ab4ac260b1fdfc2c4d65e9b436f311b0c301de7dfe57080e558d8714cc',
//             "type": "public-key",
//         },
//         {
//             "id": h'fe9703fa1d3e4997e15ddebf1588cd0b83d8efd85b4ca2e45f6f83a946f2acf5',
//             "type": "public-key",
//         },
//     ],
//     6: {"credProtect": 2},
//     7: {"rk": true},
//     8: h'3a0bc8d0eab4f9c3362f9652f4e9da16',
//     9: 1,
// }
//
// ctap_request: response status code 0x00, response length 370 bytes
// hex(370): a301667061636b65640259011274a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0c5000000010076631bd4a0427f57730ec71c9e02790080011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77a501020326200121582016286520196b96a8d8fb1e2f937d9b0a8430e633526ae49b4c5a5c4c578e7b9222582012128f11e2ebfa833f3049caaae3ca922ccd34c08cf624c09f3418f6aaa70c6da16b6372656450726f746563740203a263616c67266373696758463044022023c4dd60b8608b6fdcb15a10966942e7b43b547d4a392252a08fd28fbb4a438002201d78a339e18ea1235e73c86634cce505ac5ba85835f8b67a36cfe1f2dc002595
// {
//     1: "packed",
//     2: h'74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0c5000000010076631bd4a0427f57730ec71c9e02790080011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77a501020326200121582016286520196b96a8d8fb1e2f937d9b0a8430e633526ae49b4c5a5c4c578e7b9222582012128f11e2ebfa833f3049caaae3ca922ccd34c08cf624c09f3418f6aaa70c6da16b6372656450726f7465637402',
//     3: {
//         "alg": -7,
//         "sig": h'3044022023c4dd60b8608b6fdcb15a10966942e7b43b547d4a392252a08fd28fbb4a438002201d78a339e18ea1235e73c86634cce505ac5ba85835f8b67a36cfe1f2dc002595',
//     },
// }
//
// authData (0x03):
// 74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0c5000000010076631bd4a0427f57730ec71c9e02790080011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77a501020326200121582016286520196b96a8d8fb1e2f937d9b0a8430e633526ae49b4c5a5c4c578e7b9222582012128f11e2ebfa833f3049caaae3ca922ccd34c08cf624c09f3418f6aaa70c6da16b6372656450726f7465637402
// 548 HEX chars = 274 bytes
// 32 rpIdHash = SHA-256("webauthn.io")
//      74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0
//  1 flags = 0xc5 = 0b1100_0101 = UP | UV | AT | ED
//  4 signCount (BE) = 0x00000001
//    attested credential data
//      16 aaguid = 0076631bd4a0427f57730ec71c9e0279
//       2 credentialIdLength (BE) = 0x0080 = 128
//     128 credentialId = 011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77
//         credentialPublicKey
//           a501020326200121582016286520196b96a8d8fb1e2f937d9b0a8430e633526ae49b4c5a5c4c578e7b9222582012128f11e2ebfa833f3049caaae3ca922ccd34c08cf624c09f3418f6aaa70c6d
//           {
//               1: 2,
//               3: -7,
//               -1: 1,
//               -2: h'16286520196b96a8d8fb1e2f937d9b0a8430e633526ae49b4c5a5c4c578e7b92',
//               -3: h'12128f11e2ebfa833f3049caaae3ca922ccd34c08cf624c09f3418f6aaa70c6d',
//           }
//    extensions
//      a16b6372656450726f7465637402
//      {"credProtect": 2}
//
