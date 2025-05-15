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

static inline uint8_t verify_client_data_hash(
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
		/* message */ params->clientDataHash.data, params->clientDataHash.size
	);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ params->pinUvAuthParam.data, params->pinUvAuthParam.size
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

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_label_kty));
	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_EC2));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_label_alg));
	cbor_encoding_check(cbor_encode_int(&map, COSE_ALG_ES256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_crv));
	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_EC2_crv_P256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_x));
	cbor_encoding_check(cbor_encode_byte_string(&map, x, 32));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_y));
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

static uint8_t encode_ctap_string_as_byte_string(
	CborEncoder *encoder,
	const ctap_string_t *str
) {
	CborError err;
	cbor_encoding_check(cbor_encode_byte_string(encoder, str->data, str->size));
	return CTAP2_OK;
}

static uint8_t encode_ctap_string_as_text_string(
	CborEncoder *encoder,
	const ctap_string_t *str
) {
	CborError err;
	cbor_encoding_check(cbor_encode_text_string(encoder, (const char *) str->data, str->size));
	return CTAP2_OK;
}

static uint8_t encode_pub_key_cred_user_entity(
	CborEncoder *encoder,
	const CTAP_userEntity *user,
	const bool include_user_identifiable_info
) {

	assert(ctap_param_is_present(user, CTAP_userEntity_id));

	uint8_t ret;
	CborError err;
	CborEncoder map;

	size_t num_items = 1; // user.id (also called userHandle) is always included

	// only add user identifiable information (name, displayName, icon)
	// if it is desired (include_user_identifiable_info)
	if (include_user_identifiable_info) {
		if (ctap_param_is_present(user, CTAP_userEntity_name)) {
			num_items++;
		}
		if (ctap_param_is_present(user, CTAP_userEntity_displayName)) {
			num_items++;
		}
	}

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, num_items));

	cbor_encoding_check(cbor_encode_text_string(&map, "id", 2));
	ctap_check(encode_ctap_string_as_byte_string(&map, &user->id));

	if (include_user_identifiable_info && ctap_param_is_present(user, CTAP_userEntity_name)) {
		cbor_encoding_check(cbor_encode_text_string(&map, "name", 4));
		ctap_check(encode_ctap_string_as_text_string(&map, &user->name));
	}

	if (include_user_identifiable_info && ctap_param_is_present(user, CTAP_userEntity_displayName)) {
		cbor_encoding_check(cbor_encode_text_string(&map, "displayName", 11));
		ctap_check(encode_ctap_string_as_text_string(&map, &user->displayName));
	}

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t encode_rp_entity(
	CborEncoder *encoder,
	const CTAP_rpId *rp_id
) {

	uint8_t ret;
	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));

	cbor_encoding_check(cbor_encode_text_string(&map, "id", 2));
	ctap_check(encode_ctap_string_as_text_string(&map, &rp_id->id));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

void ctap_compute_rp_id_hash(uint8_t *rp_id_hash, const CTAP_rpId *rp_id) {
	sha256_ctx_t sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, rp_id->id.data, rp_id->id.size);
	sha256_final(&sha256_ctx, rp_id_hash);
}

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
	uint8_t message_hash[CTAP_SHA256_HASH_SIZE];
	sha256_ctx_t sha256_ctx;
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

#define CTAP_MEMORY_MAX_NUM_CREDENTIALS 50
static size_t num_stored_credentials = 0;
static size_t num_stored_discoverable_credentials = 0;
static ctap_credentials_map_key credentials_map_keys[CTAP_MEMORY_MAX_NUM_CREDENTIALS];
static ctap_credentials_map_value credentials_map_values[CTAP_MEMORY_MAX_NUM_CREDENTIALS];

bool ctap_credential_matches_rp_id_hash(
	const ctap_credentials_map_key *key,
	const uint8_t *rp_id_hash
) {
	return memcmp(key->rpId.hash, rp_id_hash, CTAP_SHA256_HASH_SIZE) == 0;
}

bool ctap_credential_matches_rp(
	const ctap_credentials_map_key *key,
	const CTAP_rpId *rp_id
) {
	const bool rp_id_matches = (key->truncated & CTAP_truncated_rpId) == 0u
		// if the rpId was NOT truncated, then we can compare the exact rpId values
		? ctap_string_matches(&key->rpId.id, &rp_id->id)
		// otherwise, our only option is to compare the hashes
		: ctap_credential_matches_rp_id_hash(key, rp_id->hash);
	if (!rp_id_matches) {
		return false;
	}
	// debugging assert: rp_id_matches => the hashes are equal
	assert(ctap_credential_matches_rp_id_hash(key, rp_id->hash));
	return true;
}

static int find_credential_index(
	const CTAP_rpId *rp_id,
	const CTAP_userHandle *user_handle
) {

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}
		if (!ctap_credential_matches_rp(key, rp_id)) {
			continue;
		}
		if (!ctap_string_matches(&key->user.id, user_handle)) {
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

bool ctap_maybe_truncate_string(
	const ctap_string_t *const input_str,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	size_t *const stored_size
) {

	// see WebAuthn 6.4. String Handling (6.4.1.2. String Truncation by Authenticators)
	//   https://w3c.github.io/webauthn/#sctn-strings

	// no truncation needed
	if (input_str->size <= storage_buffer_size) {
		memcpy(storage_buffer, input_str->data, input_str->size);
		*stored_size = input_str->size;
		return false;
	}

	assert(input_str->size > storage_buffer_size);
	// TODO:
	//  The truncation SHOULD respect UTF-8 code point boundaries,
	//  and MAY respect grapheme cluster boundaries.
	//  The resulting truncated value MAY be shorter than the chosen size limit
	//  but MUST NOT be shorter than the longest prefix substring
	//  that satisfies the size limit and ends on a grapheme cluster boundary.
	memcpy(storage_buffer, input_str->data, storage_buffer_size);
	*stored_size = storage_buffer_size;
	return true;

}

bool ctap_maybe_truncate_rp_id(
	const ctap_string_t *const rp_id,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	size_t *const stored_size
) {

	// see 6.8.7. Truncation of relying party identifiers
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
	// see WebAuthn 6.4. String Handling (6.4.1.2. String Truncation by Authenticators)
	//   https://w3c.github.io/webauthn/#sctn-strings

	// If authenticators store relying party identifiers at all, they MUST store at least 32 bytes.
	assert(storage_buffer_size >= 32);

	if (rp_id->size <= storage_buffer_size) {
		memcpy(storage_buffer, rp_id->data, rp_id->size);
		*stored_size = rp_id->size;
		return false;
	}

	size_t used = 0;

	// [protocol]://[host]
	const uint8_t *colon_position = memchr(rp_id->data, ':', rp_id->size);
	if (colon_position != NULL) {
		assert(rp_id->data <= colon_position && colon_position < (rp_id->data + rp_id->size));
		const size_t protocol_len = colon_position - rp_id->data + 1; // + 1 for the colon itself
		// protocol strings are preserved if possible
		const size_t to_copy = protocol_len <= storage_buffer_size
			? protocol_len
			: storage_buffer_size;
		assert(to_copy <= storage_buffer_size);
		memcpy(storage_buffer, rp_id->data, to_copy);
		used += to_copy;
	}

	if (storage_buffer_size - used < 3) {
		*stored_size = used;
		return true;
	}

	// U+2026, horizontal ellipsis
	storage_buffer[used++] = 0xe2;
	storage_buffer[used++] = 0x80;
	storage_buffer[used++] = 0xa6;

	const size_t to_copy = storage_buffer_size - used;
	assert(used + to_copy == storage_buffer_size);
	memcpy(&storage_buffer[used], rp_id->data + rp_id->size - to_copy, to_copy);
	*stored_size = storage_buffer_size;
	return true;

}

bool ctap_store_arbitrary_length_string(
	const ctap_string_t *const input_str,
	ctap_string_t *const str,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	ctap_truncate_str truncate_fn
) {

	assert(truncate_fn != NULL);

	str->data = storage_buffer;

	const bool was_truncated = truncate_fn(
		input_str,
		storage_buffer,
		storage_buffer_size,
		&str->size
	);

	assert(str->size <= storage_buffer_size);
	assert(str->size <= input_str->size);

	if (was_truncated) {
		debug_log(
			red("truncated string from %" PRIsz " bytes to %" PRIsz " bytes for storage (max %" PRIsz " bytes)") nl,
			input_str->size, str->size, storage_buffer_size
		);
	}

	return was_truncated;

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

				static_assert(
					sizeof(key->rpId.hash) == sizeof(rp_id->hash),
					"sizeof(key->rpId.hash) == sizeof(rp_id->hash)"
				);
				memcpy(key->rpId.hash, rp_id->hash, sizeof(key->rpId_hash));
				if (ctap_store_arbitrary_length_string(
					&rp_id->id,
					&key->rpId.id,
					key->rpId_buffer,
					sizeof(key->rpId_buffer),
					ctap_maybe_truncate_rp_id
				)) {
					key->truncated |= CTAP_truncated_rpId;
				}

				key->user.present = user->present;

				// The WebAuthn spec defines a maximum size of 64 bytes for the userHandle (user.id).
				static_assert(
					sizeof(key->userId_buffer) == CTAP_USER_ENTITY_ID_MAX_SIZE,
					"sizeof(key->userId_buffer) == CTAP_USER_ENTITY_ID_MAX_SIZE"
				);
				// Note: This should already be ensured by the checks in parse_user_entity().
				if ((
					key->user.id.size > sizeof(key->userId_buffer)
					|| !ctap_param_is_present(user, CTAP_userEntity_id)
				)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				if (ctap_store_arbitrary_length_string(
					&user->id,
					&key->user.id,
					key->userId_buffer,
					sizeof(key->userId_buffer),
					ctap_maybe_truncate_string
				)) {
					// This should never be reached thanks to the
					// `key->user.id.size > sizeof(key->userId_buffer)` check above.
					assert(false);
				}

				if (ctap_param_is_present(user, CTAP_userEntity_name)) {
					if (ctap_store_arbitrary_length_string(
						&user->name,
						&key->user.name,
						key->userName_buffer,
						sizeof(key->userName_buffer),
						ctap_maybe_truncate_string
					)) {
						key->truncated |= CTAP_truncated_userName;
					}
				}
				if (ctap_param_is_present(user, CTAP_userEntity_displayName)) {
					if (ctap_store_arbitrary_length_string(
						&user->displayName,
						&key->user.displayName,
						key->userDisplayName_buffer,
						sizeof(key->userDisplayName_buffer),
						ctap_maybe_truncate_string
					)) {
						key->truncated |= CTAP_truncated_userDisplayName;
					}
				}

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

	num_stored_credentials++;
	if (credential->discoverable) {
		num_stored_discoverable_credentials++;
	}

	return CTAP2_OK;

}

static uint8_t delete_credential(const int idx) {

	assert(0 <= idx && idx < CTAP_MEMORY_MAX_NUM_CREDENTIALS);

	ctap_credentials_map_key *key = &credentials_map_keys[idx];
	ctap_credentials_map_value *value = &credentials_map_values[idx];

	assert(key->used);

	num_stored_credentials--;
	if (value->discoverable) {
		num_stored_discoverable_credentials--;
	}

	memset(key, 0, sizeof(ctap_credentials_map_key)); // ensures key->used == false
	memset(value, 0, sizeof(ctap_credentials_map_value));

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
	ctap_check(verify_client_data_hash(state, params, pin_protocol));
	// 2. Verify that the pinUvAuthToken has the required permissions,
	//    if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if (!ctap_pin_uv_auth_token_has_permissions(state, permissions)) {
		debug_log(
			red("pinUvAuthToken does not have the required permissions:"
				" current=%" PRIu32 " required=%" PRIu32) nl,
			state->pin_uv_auth_token_state.permissions,
			permissions
		);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// 3. If the pinUvAuthToken has a permissions RP ID associated:
	//    1. If the permissions RP ID does NOT match the rp.id in this request,
	//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if ((
		state->pin_uv_auth_token_state.rpId_set
		&& memcmp(state->pin_uv_auth_token_state.rpId_hash, params->rpId.hash, CTAP_SHA256_HASH_SIZE) != 0
	)) {
		debug_log(
			red("pinUvAuthToken RP ID mismatch: required='%.*s' hash = "),
			(int) params->rpId.id.size, params->rpId.id.data
		);
		dump_hex(params->rpId.hash, sizeof(params->rpId.hash));
		debug_log("pinUvAuthToken associated RP ID hash = ");
		dump_hex(state->pin_uv_auth_token_state.rpId_hash, sizeof(state->pin_uv_auth_token_state.rpId_hash));
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
	// If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
	if (!ctap_pin_uv_auth_token_get_user_verified_flag_value(state)) {
		debug_log(red("pinUvAuthToken user_verified=false") nl);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	// If the pinUvAuthToken does not have a permissions RP ID associated:
	// Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
	if (!state->pin_uv_auth_token_state.rpId_set) {
		ctap_compute_rp_id_hash(state->pin_uv_auth_token_state.rpId_hash, &params->rpId);
		state->pin_uv_auth_token_state.rpId_set = true;
		debug_log(
			"pinUvAuthToken did not have RP ID associated, setting to '%.*s' hash = ",
			(int) params->rpId.id.size, params->rpId.id.data
		);
		dump_hex(state->pin_uv_auth_token_state.rpId_hash, sizeof(state->pin_uv_auth_token_state.rpId_hash));
	}
	return CTAP2_OK;
}

static uint8_t ensure_user_present(ctap_state_t *state, const bool pinUvAuthParam_present) {
	const bool user_present = pinUvAuthParam_present && ctap_pin_uv_auth_token_get_user_present_flag_value(state);
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
		if (!ctap_credential_matches_rp(&credentials_map_keys[idx], rpId)) {
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
		//   What if is the pinUvAuthParam is invalid here?
		//   Note that it is validated only if !allow_no_verification && state->persistent.is_pin_set (see Step 11).
		const bool user_present = pinUvAuthParam_present && ctap_pin_uv_auth_token_get_user_present_flag_value(state);
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

static bool should_add_credential_to_list(
	const ctap_credentials_map_value *cred_value,
	const bool is_from_allow_list,
	const bool response_has_uv
) {
	// 6.2.2. authenticatorGetAssertion Algorithm, 7. Locate all credentials ...
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#op-getassn-step-locate-credentials
	// 7.4. ... if credential protection for a credential
	//      is marked as userVerificationRequired, and the "uv" bit is false in the response,
	//      remove that credential from the applicable credentials list.
	if ((
		cred_value->credProtect == CTAP_extension_credProtect_3_userVerificationRequired
		&& !response_has_uv
	)) {
		// do not add this credential to the list
		return false;
	}
	// 7.5. ... if credential protection for a credential
	//      is marked as userVerificationOptionalWithCredentialIDList and there is no allowList passed by
	//      the client and the "uv" bit is false in the response, remove that credential
	//      from the applicable credentials list.
	if ((
		cred_value->credProtect == CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList
		&& !is_from_allow_list
		&& !response_has_uv
	)) {
		// do not add this credential to the list
		return false;
	}
	return true;
}

static uint8_t process_allow_list(
	const CborValue *allowList,
	const CTAP_rpId *rpId,
	const bool response_has_uv,
	ctap_credential *credentials,
	size_t *const num_credentials,
	const size_t max_num_credentials
) {

	debug_log("process_allow_list" nl);

	uint8_t ret;
	size_t credentials_num = 0;

	ctap_parse_pub_key_cred_desc_list_ctx list_ctx;
	ctap_check(ctap_parse_pub_key_cred_desc_list_init(&list_ctx, allowList));

	CTAP_credDesc *cred_desc;
	// iterate over ALL credential descriptors to parse and validate them,
	// find the first applicable credential
	while (true) {

		// parse and validate each credential descriptors
		ctap_check(ctap_parse_pub_key_cred_desc_list_next_cred(&list_ctx, &cred_desc));

		// if the end of the list, stop iteration
		if (cred_desc == NULL) {
			break;
		}

		int idx = lookup_credential_by_desc(cred_desc);

		if (idx == -1) {
			debug_log("process_allow_list: skipping unknown credential ID" nl);
			continue;
		}

		ctap_credentials_map_key *key = &credentials_map_keys[idx];

		if (!ctap_credential_matches_rp(key, rpId)) {
			debug_log("process_allow_list: skipping credential ID that is bound to a different RP" nl);
			continue;
		}

		ctap_credentials_map_value *value = &credentials_map_values[idx];

		if (!should_add_credential_to_list(value, true, response_has_uv)) {
			debug_log("process_allow_list: skipping credential due to its credProtect" nl);
			continue;
		}

		if (credentials_num == max_num_credentials) {
			error_log(
				red("process_allow_list: credentials_max_size (%" PRIsz ") reached") nl,
				max_num_credentials
			);
			return CTAP1_ERR_INVALID_LENGTH;
		}
		ctap_credential *credential = &credentials[credentials_num++];
		credential->key = key;
		credential->value = value;

	}

	*num_credentials = credentials_num;

	return CTAP2_OK;

}

static uint8_t find_discoverable_credentials_by_rp_id(
	const CTAP_rpId *rp_id,
	const uint8_t *rp_id_hash,
	const bool response_has_uv,
	ctap_credential *credentials,
	size_t *const num_credentials,
	const size_t max_num_credentials
) {

	debug_log("find_credentials_by_rp_id" nl);

	assert(rp_id != NULL || rp_id_hash != NULL);

	size_t credentials_num = 0;

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}

		if (rp_id != NULL) {
			if (!ctap_credential_matches_rp(key, rp_id)) {
				continue;
			}
		} else if (rp_id_hash != NULL) {
			if (!ctap_credential_matches_rp_id_hash(key, rp_id_hash)) {
				continue;
			}
		} else {
			assert(false);
			continue;
		}

		ctap_credentials_map_value *value = &credentials_map_values[i];

		if (!value->discoverable) {
			debug_log("find_credentials_by_rp_id: skipping non-discoverable credential" nl);
			continue;
		}

		if (!should_add_credential_to_list(value, false, response_has_uv)) {
			debug_log("find_credentials_by_rp_id: skipping credential due to its credProtect" nl);
			continue;
		}

		if (credentials_num == max_num_credentials) {
			error_log(
				red("find_credentials_by_rp_id: credentials_max_size (%" PRIsz ") reached") nl,
				max_num_credentials
			);
			return CTAP1_ERR_INVALID_LENGTH;
		}
		ctap_credential *credential = &credentials[credentials_num++];
		credential->key = key;
		credential->value = value;

	}

	*num_credentials = credentials_num;

	return CTAP2_OK;

}

static bool is_rp_id_in_the_list(
	const CTAP_rpId *rp_id,
	CTAP_rpId **rp_ids,
	const size_t num_rp_ids
) {

	for (size_t i = 0; i < num_rp_ids; ++i) {
		if (memcmp(rp_ids[i]->hash, rp_id->hash, CTAP_SHA256_HASH_SIZE) == 0) {
			return true;
		}
	}

	return false;

}

static uint8_t enumerate_rp_ids_of_discoverable_credentials(
	CTAP_rpId **rp_ids,
	size_t *const num_rp_ids,
	const size_t max_num_rp_ids
) {

	debug_log("enumerate_rp_ids_of_discoverable_credentials" nl);

	size_t current_num_rp_ids = 0;

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}

		ctap_credentials_map_value *value = &credentials_map_values[i];

		if (!value->discoverable) {
			debug_log("enumerate_rp_ids_of_discoverable_credentials: skipping non-discoverable credential" nl);
			continue;
		}

		if (is_rp_id_in_the_list(&key->rpId, rp_ids, current_num_rp_ids)) {
			debug_log("enumerate_rp_ids_of_discoverable_credentials: skipping adding duplicate RP ID" nl);
			continue;
		}

		if (current_num_rp_ids == max_num_rp_ids) {
			error_log(
				red("enumerate_rp_ids_of_discoverable_credentials: max_num_rp_ids (%" PRIsz ") reached") nl,
				max_num_rp_ids
			);
			return CTAP2_ERR_REQUEST_TOO_LARGE;
		}
		rp_ids[current_num_rp_ids++] = &key->rpId;
	}

	*num_rp_ids = current_num_rp_ids;

	return CTAP2_OK;

}

uint8_t ctap_make_credential(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	uint8_t ret;
	CborError err;

	CTAP_makeCredential mc;
	CTAP_mc_ga_common *const params = &mc.common;
	ctap_check(ctap_parse_make_credential(it, &mc));

	const bool pinUvAuthParam_present = ctap_param_is_present(params, CTAP_makeCredential_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.1.2. authenticatorMakeCredential Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg
	// see also WebAuthn 6.3.2. The authenticatorMakeCredential Operation
	// https://w3c.github.io/webauthn/#sctn-op-make-cred

	// rpId_hash is needed throughout the whole algorithm, so we compute it right away.
	ctap_compute_rp_id_hash(params->rpId.hash, &params->rpId);

	// 1. + 2.
	ctap_check(handle_pin_uv_auth_param_and_protocol(
		state,
		pinUvAuthParam_present,
		params->pinUvAuthParam.size,
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
	ctap_pin_uv_auth_token_clear_user_present_flag(state);
	ctap_pin_uv_auth_token_clear_user_verified_flag(state);
	ctap_pin_uv_auth_token_clear_permissions_except_lbw(state);

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
	ctap_check(store_credential(
		&params->rpId,
		&mc.user,
		&credential
	));

	// 19. Generate an attestation statement for the newly-created credential using clientDataHash,
	//     taking into account the value of the enterpriseAttestation parameter, if present,
	//     as described above in Step 9.
	memcpy(auth_data.fixed_header.rpIdHash, params->rpId.hash, CTAP_SHA256_HASH_SIZE);
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
		params->clientDataHash.data,
		&credential
	));
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t generate_get_assertion_response(
	CborEncoder *encoder,
	const ctap_credential *const credential,
	const uint8_t *const auth_data_rp_id_hash,
	const uint8_t *const client_data_hash_hash,
	const uint8_t auth_data_flags,
	const size_t num_credentials
) {

	uint8_t ret;

	// 13. Sign the clientDataHash along with authData with the selected credential
	//     using the structure specified in

	uint8_t public_key[64];
	if (uECC_compute_public_key(
		credential->value->private_key,
		public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return CTAP1_ERR_OTHER;
	}

	CTAP_authenticator_data auth_data;
	memcpy(auth_data.fixed_header.rpIdHash, auth_data_rp_id_hash, sizeof(auth_data.fixed_header.rpIdHash));
	auth_data.fixed_header.flags = auth_data_flags;
	credential->value->signCount++;
	auth_data.fixed_header.signCount = lion_htonl(credential->value->signCount);

	size_t auth_data_variable_size = 0u;
	const size_t auth_data_variable_max_size = sizeof(auth_data.variable_data);

	// if (ctap_param_is_present(params, CTAP_getAssertion_extensions)) {
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
		client_data_hash_hash,
		credential->value,
		asn1_der_sig,
		&asn1_der_sig_size
	));

	CborError err;
	CborEncoder map;

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(
		encoder,
		&map,
		num_credentials ? 5 : 4
	));
	// credential (0x01)
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_credential));
	ctap_check(encode_pub_key_cred_desc(&map, sizeof(credential->value->id), credential->value->id));
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
	//   User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity
	//   MUST NOT be returned if user verification was not done by the authenticator
	//   in the original authenticatorGetAssertion call.
	bool include_user_identifiable_info = (auth_data_flags & CTAP_authenticator_data_flags_uv) != 0u;
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_user));
	ctap_check(encode_pub_key_cred_user_entity(&map, &credential->key->user, include_user_identifiable_info));
	if (num_credentials > 0) {
		// numberOfCredentials (0x05)
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_getAssertion_res_numberOfCredentials));
		cbor_encoding_check(cbor_encode_uint(&map, num_credentials));
	}
	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

uint8_t ctap_get_assertion(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	uint8_t ret;

	CTAP_getAssertion ga;
	CTAP_mc_ga_common *const params = &ga.common;
	ctap_check(ctap_parse_get_assertion(it, &ga));

	const bool pinUvAuthParam_present = ctap_param_is_present(params, CTAP_getAssertion_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.2.2. authenticatorGetAssertion Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-getAssert-authnr-alg
	// see also WebAuthn 6.3.3. The authenticatorGetAssertion Operation
	// https://w3c.github.io/webauthn/#sctn-op-get-assertion

	// rpId_hash is needed throughout the whole algorithm, so we compute it right away.
	ctap_compute_rp_id_hash(params->rpId.hash, &params->rpId);

	// 1. + 2.
	ctap_check(handle_pin_uv_auth_param_and_protocol(
		state,
		pinUvAuthParam_present,
		params->pinUvAuthParam.size,
		ctap_param_is_present(params, CTAP_getAssertion_pinUvAuthProtocol),
		params->pinUvAuthProtocol,
		&pin_protocol
	));

	// 3. Create a new authenticatorGetAssertion response structure
	//    and initialize both its "uv" bit and "up" bit as false.
	uint32_t auth_data_flags = 0u;

	// 4. If the options parameter is present, process all option keys and values present in the parameter.
	//    Treat any option keys that are not understood as absent.
	// 4.5. If the "up" option is not present then, let the "up" option be treated
	//      as being present with the value true.
	const bool up = get_option_value_or_true(&params->options, CTAP_ma_ga_option_up);
	debug_log("option up=%d" nl, up);
	if (ctap_param_is_present(params, CTAP_getAssertion_options)) {
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
			auth_data_flags |= CTAP_authenticator_data_flags_uv;
		}
		// 2. If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
		//    and that the authenticator supports an enabled built-in user verification method, see Step 4):
		//    (not applicable to LionKey)
	}

	ctap_discard_stateful_command_state(state);
	ctap_get_assertion_state_t *ga_state = &state->stateful_command_state.get_assertion;
	ga_state->num_credentials = 0;
	ga_state->next_credential_idx = 0;
	const size_t max_num_credentials = sizeof(ga_state->credentials) / sizeof(ctap_credential);
	const bool response_has_uv = (auth_data_flags & CTAP_authenticator_data_flags_uv) != 0u;
	// 7. Locate all credentials that are eligible for retrieval under the specified criteria:
	//    Note: Our implementation also performs steps 7.3., 7.4., and 7.5. at the same time.
	if (ctap_param_is_present(params, CTAP_getAssertion_allowList)) {
		// 7.1. If the allowList parameter is present and is non-empty,
		//      locate all denoted credentials created by this authenticator and bound to the specified rpId.
		ctap_check(process_allow_list(
			&ga.allowList,
			&params->rpId,
			response_has_uv,
			ga_state->credentials,
			&ga_state->num_credentials,
			max_num_credentials
		));
	} else {
		// 7.2. If an allowList is not present, locate all discoverable credentials
		//      that are created by this authenticator and bound to the specified rpId.
		// TODO: (stems from Step 12.1.2.)
		//   Order the credentials in the applicable credentials list
		//   by the time when they were created in reverse order.
		//   (I.e. the first credential is the most recently created.)
		ctap_check(find_discoverable_credentials_by_rp_id(
			&params->rpId,
			NULL,
			response_has_uv,
			ga_state->credentials,
			&ga_state->num_credentials,
			max_num_credentials
		));

	}
	// 7.6. If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
	if (ga_state->num_credentials == 0) {
		info_log("no credentials found" nl);
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
		auth_data_flags |= CTAP_authenticator_data_flags_up;
		// 9.4. Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
		//      Note: This consumes both the "user present state", sometimes referred to as the "cached UP",
		//      and the "user verified state", sometimes referred to as "cached UV".
		//      These functions are no-ops if there is not an in-use pinUvAuthToken.
		ctap_pin_uv_auth_token_clear_user_present_flag(state);
		ctap_pin_uv_auth_token_clear_user_verified_flag(state);
		ctap_pin_uv_auth_token_clear_permissions_except_lbw(state);
	}

	// extensions processing

	// 10. If the extensions parameter is present:
	if (ctap_param_is_present(params, CTAP_getAssertion_extensions)) {
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

	// 11. If the allowList parameter is present: ...
	//     (nothing to do here, already handled by our other logic)

	// 12. If allowList is not present:
	// 12.1. If numberOfCredentials is one, select that credential.
	//       (nothing to do here, already handled by our other logic).
	// 12.2. If numberOfCredentials is more than one:
	// 12.2.1. Order the credentials ... (already handled by our modified 7.2.)
	// (not applicable) 12.2.3. If authenticator has a display ...
	// 12.2.2. If the authenticator does not have a display,
	//         or the authenticator does have a display and the "uv" and "up" options are false:
	if (!ctap_param_is_present(params, CTAP_getAssertion_allowList) && ga_state->num_credentials > 1) {
		memcpy(ga_state->client_data_hash, params->clientDataHash.data, sizeof(ga_state->client_data_hash));
		ga_state->auth_data_flags = auth_data_flags;
		state->stateful_command_state.active_cmd = CTAP_STATEFUL_CMD_GET_ASSERTION;
		// 12.2.2.3. Start a timer. This is used during authenticatorGetNextAssertion command.
		//           This step is OPTIONAL if transport is done over NFC.
		ctap_update_stateful_command_timer(state);
	}

	memcpy(ga_state->auth_data_rp_id_hash, params->rpId.hash, CTAP_SHA256_HASH_SIZE);

	// 13. Sign the clientDataHash along with authData.
	ctap_check(generate_get_assertion_response(
		encoder,
		&ga_state->credentials[ga_state->next_credential_idx],
		ga_state->auth_data_rp_id_hash,
		params->clientDataHash.data,
		auth_data_flags,
		ga_state->num_credentials
	));

	if (state->stateful_command_state.active_cmd == CTAP_STATEFUL_CMD_GET_ASSERTION) {
		// 12.2.2.2. Create a credential counter (credentialCounter) and set it to 1.
		//    This counter signifies the next credential to be returned by the authenticator,
		//    assuming zero-based indexing.
		ga_state->next_credential_idx++;
	} else {
		// We could just leave the partial state in memory since it's not valid anyway
		// (because, at this point, stateful_command_state.active_cmd == CTAP_STATEFUL_CMD_NONE).
		// However, as a good practice, we want to avoid keeping any potentially sensitive state
		// in memory longer than necessary. To avoid unnecessary large memset()
		// in ctap_discard_stateful_command_state(), we manually clean up the partial state.
		memset(ga_state->auth_data_rp_id_hash, 0, CTAP_SHA256_HASH_SIZE);
		static_assert(
			sizeof(ga_state->credentials[0]) == sizeof(ctap_credential),
			"sizeof(ga_state->credentials[0]) == sizeof(ctap_credential)"
		);
		memset(ga_state->credentials, 0, sizeof(ga_state->credentials[0]) * ga_state->num_credentials);
		ga_state->num_credentials = 0;
	}

	return CTAP2_OK;

}

uint8_t ctap_get_next_assertion(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	// This command does not take any parameters.
	lion_unused(it);

	// 6.3. authenticatorGetNextAssertion (0x08)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetNextAssertion

	uint8_t ret;

	// When this command is received, the authenticator performs the following procedure:

	// 1. If authenticator does not remember any authenticatorGetAssertion parameters,
	//    return CTAP2_ERR_NOT_ALLOWED.
	// 2. If the credentialCounter is equal to or greater than numberOfCredentials,
	//    return CTAP2_ERR_NOT_ALLOWED.
	//    Note:
	//      In our implementation, we discard the state as soon as the iteration reaches the end,
	//      so only need to check the ga_state->valid.
	// 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion
	//    is greater than 30 seconds, discard the current authenticatorGetAssertion state
	//    and return CTAP2_ERR_NOT_ALLOWED. This step is OPTIONAL if transport is done over NFC.
	//    (implemented centrally for all stateful commands in ctap_request() by discarding the state
	//     when the timer since the last call is greater than 30 seconds)
	if (state->stateful_command_state.active_cmd != CTAP_STATEFUL_CMD_GET_ASSERTION) {
		return CTAP2_ERR_NOT_ALLOWED;
	}

	ctap_get_assertion_state_t *ga_state = &state->stateful_command_state.get_assertion;

	// This should be ensured by the check at the end of the function,
	// which discards the state as soon as the iteration reaches the end
	// (i.e., if ga_state->next_credential_idx == ga_state->num_credentials).
	assert(ga_state->next_credential_idx < ga_state->num_credentials);

	// 6. Sign the clientDataHash along with authData. (also handles Step 5)
	ctap_check(generate_get_assertion_response(
		encoder,
		// 4. Select the credential indexed by credentialCounter.
		&ga_state->credentials[ga_state->next_credential_idx],
		ga_state->auth_data_rp_id_hash,
		ga_state->client_data_hash,
		ga_state->auth_data_flags,
		0 // numberOfCredentials (0x05) is omitted for the authenticatorGetNextAssertion
	));

	// 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
	ctap_update_stateful_command_timer(state);
	// 8. Increment credentialCounter.
	ga_state->next_credential_idx++;
	// Discard the state as soon as the iteration finishes.
	if (ga_state->next_credential_idx == ga_state->num_credentials) {
		ctap_discard_stateful_command_state(state);
	}

	return CTAP2_OK;

}

static inline uint8_t verify_credential_management_params(
	ctap_state_t *state,
	const CTAP_credentialManagement *params,
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
		/* message */ &params->subCommand, sizeof(params->subCommand)
	);
	if (params->subCommandParams.raw_size > 0) {
		pin_protocol->verify_update(
			pin_protocol,
			&verify_ctx,
			/* message */ params->subCommandParams.raw, params->subCommandParams.raw_size
		);
	}
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ params->pinUvAuthParam.data, params->pinUvAuthParam.size
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	if (!ctap_pin_uv_auth_token_has_permissions(state, CTAP_clientPIN_pinUvAuthToken_permission_cm)) {
		debug_log(
			red("pinUvAuthToken does not have the cm permission:"
				" current=%" PRIu32 " required=%" PRIu32) nl,
			state->pin_uv_auth_token_state.permissions,
			(uint32_t) CTAP_clientPIN_pinUvAuthToken_permission_cm
		);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	return CTAP2_OK;
}

static uint8_t credential_management_get_creds_metadata(ctap_state_t *const state, CborEncoder *const encoder) {

	// the pinUvAuthToken used for getCredsMetadata must NOT have a permissions RP ID associated
	if (state->pin_uv_auth_token_state.rpId_set) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));
	cbor_encoding_check(cbor_encode_uint(
		&map, CTAP_credentialManagement_res_existingResidentCredentialsCount
	));
	cbor_encoding_check(cbor_encode_uint(
		&map, num_stored_discoverable_credentials
	));
	cbor_encoding_check(cbor_encode_uint(
		&map, CTAP_credentialManagement_res_maxPossibleRemainingResidentCredentialsCount
	));
	cbor_encoding_check(cbor_encode_uint(
		&map, CTAP_MEMORY_MAX_NUM_CREDENTIALS - num_stored_discoverable_credentials
	));
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t encode_credential_management_enumerate_rps_response(
	CborEncoder *encoder,
	const CTAP_rpId *rp_id,
	const size_t num_rps
) {

	uint8_t ret;
	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, num_rps != 0 ? 3 : 2));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_rp));
	ctap_check(encode_rp_entity(&map, rp_id));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_rpIDHash));
	cbor_encoding_check(cbor_encode_byte_string(&map, rp_id->hash, sizeof(rp_id->hash)));

	if (num_rps != 0) {
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_totalRPs));
		cbor_encoding_check(cbor_encode_uint(&map, num_rps));
	}

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t credential_management_enumerate_rps_begin(ctap_state_t *const state, CborEncoder *const encoder) {

	// the pinUvAuthToken used for enumerateRPsBegin must NOT have a permissions RP ID associated
	if (state->pin_uv_auth_token_state.rpId_set) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	if (num_stored_discoverable_credentials == 0) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	uint8_t ret;

	ctap_discard_stateful_command_state(state);
	cred_mgmt_enumerate_rps_state_t *enumerate_rps_state = &state->stateful_command_state.cred_mgmt_enumerate_rps;
	enumerate_rps_state->num_rps = 0;
	enumerate_rps_state->next_rp_idx = 0;
	const size_t max_num_rp_ids = sizeof(enumerate_rps_state->rp_ids) / sizeof(CTAP_rpId *);
	ctap_check(enumerate_rp_ids_of_discoverable_credentials(
		enumerate_rps_state->rp_ids,
		&enumerate_rps_state->num_rps,
		max_num_rp_ids
	));

	// num_stored_discoverable_credentials > 0 => enumerate_rps_state->num_rps
	assert(enumerate_rps_state->num_rps > 0);

	ctap_check(encode_credential_management_enumerate_rps_response(
		encoder,
		enumerate_rps_state->rp_ids[enumerate_rps_state->next_rp_idx],
		enumerate_rps_state->num_rps
	));

	if (enumerate_rps_state->num_rps > 1) {
		state->stateful_command_state.active_cmd = CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_RPS;
		enumerate_rps_state->next_rp_idx++;
		ctap_update_stateful_command_timer(state);
	} else {
		// We could just leave the partial state in memory since it's not valid anyway
		// (because, at this point, stateful_command_state.active_cmd == CTAP_STATEFUL_CMD_NONE).
		// However, as a good practice, we want to avoid keeping any potentially sensitive state
		// in memory longer than necessary. To avoid unnecessary large memset()
		// in ctap_discard_stateful_command_state(), we manually clean up the partial state.
		assert(enumerate_rps_state->num_rps == 1);
		enumerate_rps_state->num_rps = 0;
		static_assert(
			sizeof(enumerate_rps_state->rp_ids[0]) == sizeof(CTAP_rpId *),
			"sizeof(enumerate_rps_state->rp_ids[0]) == sizeof(CTAP_rpId *)"
		);
		memset(
			&enumerate_rps_state->rp_ids[0],
			0,
			sizeof(enumerate_rps_state->rp_ids[0])
		);
	}

	return CTAP2_OK;

}

static uint8_t credential_management_enumerate_rps_get_next_rp(ctap_state_t *const state, CborEncoder *const encoder) {

	if (state->stateful_command_state.active_cmd != CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_RPS) {
		return CTAP2_ERR_NOT_ALLOWED;
	}

	cred_mgmt_enumerate_rps_state_t *enumerate_rps_state = &state->stateful_command_state.cred_mgmt_enumerate_rps;

	uint8_t ret;

	ctap_check(encode_credential_management_enumerate_rps_response(
		encoder,
		enumerate_rps_state->rp_ids[enumerate_rps_state->next_rp_idx],
		0 // totalRPs (0x05) is omitted for the authenticatorCredentialManagement/enumerateRPsGetNextRP
	));

	ctap_update_stateful_command_timer(state);
	enumerate_rps_state->next_rp_idx++;
	if (enumerate_rps_state->next_rp_idx == enumerate_rps_state->num_rps) {
		ctap_discard_stateful_command_state(state);
	}

	return CTAP2_OK;

}

static uint8_t encode_credential_management_enumerate_credentials_response(
	CborEncoder *encoder,
	const ctap_credential *credential,
	const size_t num_credentials
) {

	uint8_t ret;
	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(
		encoder, &map, num_credentials != 0 ? 5 : 4
	));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_user));
	ctap_check(encode_pub_key_cred_user_entity(&map, &credential->key->user, true));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_credentialID));
	ctap_check(encode_pub_key_cred_desc(
		&map, sizeof(credential->value->id), credential->value->id)
	);

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_publicKey));
	uint8_t public_key[64];
	if (uECC_compute_public_key(
		credential->value->private_key,
		public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return CTAP1_ERR_OTHER;
	}
	ctap_check(encode_public_key(&map, public_key));

	if (num_credentials != 0) {
		cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_totalCredentials));
		cbor_encoding_check(cbor_encode_uint(&map, num_credentials));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_credentialManagement_res_credProtect));
	cbor_encoding_check(cbor_encode_uint(&map, credential->value->credProtect));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

static uint8_t credential_management_enumerate_credentials_begin(
	ctap_state_t *const state,
	const CTAP_credentialManagement *const cm,
	CborEncoder *const encoder
) {

	if ((
		!ctap_param_is_present(cm, CTAP_credentialManagement_subCommandParams)
		|| !ctap_param_is_present(&cm->subCommandParams, CTAP_credentialManagement_subCommandParams_rpIDHash)
	)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// the pinUvAuthToken used for enumerateCredentialsBegin must
	// either NOT have a permissions RP ID associated,
	// or the associated permissions RP ID MUST match the RP ID of this request
	if ((
		state->pin_uv_auth_token_state.rpId_set
		&& (
			// the rpIDHash.size should already be checked by ctap_parse_credential_management()
			// (resp. parse_credential_management_subcommand_params())
			cm->subCommandParams.rpIDHash.size != CTAP_SHA256_HASH_SIZE
			|| memcmp(
				cm->subCommandParams.rpIDHash.data,
				state->pin_uv_auth_token_state.rpId_hash,
				CTAP_SHA256_HASH_SIZE
			) != 0
		)
	)) {
		debug_log(
			"credential_management_enumerate_credentials_begin: the pinUvAuthToken has a RP ID associated"
			"but it does not match the RP ID of this request" nl
		);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	if (num_stored_discoverable_credentials == 0) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	uint8_t ret;

	ctap_discard_stateful_command_state(state);
	cred_mgmt_enumerate_credentials_state_t *enumerate_credentials_state = &state->stateful_command_state.cred_mgmt_enumerate_credentials;
	enumerate_credentials_state->num_credentials = 0;
	enumerate_credentials_state->next_credential_idx = 0;
	const size_t max_num_credentials = sizeof(enumerate_credentials_state->credentials) / sizeof(ctap_credential);
	ctap_check(find_discoverable_credentials_by_rp_id(
		NULL,
		cm->subCommandParams.rpIDHash.data,
		true,
		enumerate_credentials_state->credentials,
		&enumerate_credentials_state->num_credentials,
		max_num_credentials
	));

	if (enumerate_credentials_state->num_credentials == 0) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	ctap_check(encode_credential_management_enumerate_credentials_response(
		encoder,
		&enumerate_credentials_state->credentials[enumerate_credentials_state->next_credential_idx],
		enumerate_credentials_state->num_credentials
	));

	if (enumerate_credentials_state->num_credentials > 1) {
		state->stateful_command_state.active_cmd = CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_CREDENTIALS;
		enumerate_credentials_state->next_credential_idx++;
		ctap_update_stateful_command_timer(state);
	} else {
		// We could just leave the partial state in memory since it's not valid anyway
		// (because, at this point, stateful_command_state.active_cmd == CTAP_STATEFUL_CMD_NONE).
		// However, as a good practice, we want to avoid keeping any potentially sensitive state
		// in memory longer than necessary. To avoid unnecessary large memset()
		// in ctap_discard_stateful_command_state(), we manually clean up the partial state.
		assert(enumerate_credentials_state->num_credentials == 1);
		enumerate_credentials_state->num_credentials = 0;
		static_assert(
			sizeof(enumerate_credentials_state->credentials[0]) == sizeof(ctap_credential),
			"sizeof(enumerate_credentials_state->credentials[0]) == sizeof(ctap_credential)"
		);
		memset(
			&enumerate_credentials_state->credentials[0],
			0,
			sizeof(enumerate_credentials_state->credentials[0])
		);
	}

	return CTAP2_OK;

}

static uint8_t credential_management_enumerate_credentials_get_next_credential(
	ctap_state_t *const state,
	CborEncoder *const encoder
) {

	if (state->stateful_command_state.active_cmd != CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_CREDENTIALS) {
		return CTAP2_ERR_NOT_ALLOWED;
	}

	cred_mgmt_enumerate_credentials_state_t *enumerate_credentials_state = &state->stateful_command_state.cred_mgmt_enumerate_credentials;

	uint8_t ret;

	ctap_check(encode_credential_management_enumerate_credentials_response(
		encoder,
		&enumerate_credentials_state->credentials[enumerate_credentials_state->next_credential_idx],
		0 // totalCredentials (0x09) is omitted for the authenticatorCredentialManagement/enumerateCredentialsGetNextCredential
	));

	ctap_update_stateful_command_timer(state);
	enumerate_credentials_state->next_credential_idx++;
	if (enumerate_credentials_state->next_credential_idx == enumerate_credentials_state->num_credentials) {
		ctap_discard_stateful_command_state(state);
	}

	return CTAP2_OK;

}

static uint8_t credential_management_delete_credential(
	ctap_state_t *const state,
	const CTAP_credentialManagement *const cm
) {

	ctap_discard_stateful_command_state(state);

	if ((
		!ctap_param_is_present(cm, CTAP_credentialManagement_subCommandParams)
		|| !ctap_param_is_present(&cm->subCommandParams, CTAP_credentialManagement_subCommandParams_credentialID)
	)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// find credential
	const int idx = lookup_credential_by_desc(&cm->subCommandParams.credentialID);
	if (idx == -1) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	// the pinUvAuthToken used for deleteCredential must
	// either NOT have a permissions RP ID associated,
	// or the associated permissions RP ID MUST match the RP ID of the credential
	if ((
		state->pin_uv_auth_token_state.rpId_set
		&& !ctap_credential_matches_rp_id_hash(
			&credentials_map_keys[idx], state->pin_uv_auth_token_state.rpId_hash
		)
	)) {
		debug_log(
			"credential_management_delete_credential: the pinUvAuthToken has a RP ID associated"
			"but it does not match the RP ID of the credential" nl
		);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	return delete_credential(idx);

}

static uint8_t credential_management_update_user_information(
	ctap_state_t *const state,
	const CTAP_credentialManagement *const cm
) {

	ctap_discard_stateful_command_state(state);

	if ((
		!ctap_param_is_present(cm, CTAP_credentialManagement_subCommandParams)
		|| !ctap_param_is_present(&cm->subCommandParams, CTAP_credentialManagement_subCommandParams_credentialID)
	)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// find credential
	const int idx = lookup_credential_by_desc(&cm->subCommandParams.credentialID);
	if (idx == -1) {
		return CTAP2_ERR_NO_CREDENTIALS;
	}

	// the pinUvAuthToken used for deleteCredential must
	// either NOT have a permissions RP ID associated,
	// or the associated permissions RP ID MUST match the RP ID of the credential
	if ((
		state->pin_uv_auth_token_state.rpId_set
		&& !ctap_credential_matches_rp_id_hash(
			&credentials_map_keys[idx], state->pin_uv_auth_token_state.rpId_hash
		)
	)) {
		debug_log(
			"credential_management_delete_credential: the pinUvAuthToken has a RP ID associated"
			"but it does not match the RP ID of the credential" nl
		);
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	ctap_credentials_map_key *key = &credentials_map_keys[idx];

	const CTAP_userEntity *updated_user = &cm->subCommandParams.user;

	// update of user.id is not allowed by the spec
	if (!ctap_string_matches(&updated_user->id, &key->user.id)) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Replace the matching credential's PublicKeyCredentialUserEntity's
	// name, displayName with the passed-in user details.
	// If a field is not present in the passed-in user details, or it is present and empty,
	// remove it from the matching credential's PublicKeyCredentialUserEntity.
	if (ctap_param_is_present(updated_user, CTAP_userEntity_name) && updated_user->name.size > 0) {
		ctap_set_present(&key->user, CTAP_userEntity_name);
		if (ctap_store_arbitrary_length_string(
			&updated_user->name,
			&key->user.name,
			key->userName_buffer,
			sizeof(key->userName_buffer),
			ctap_maybe_truncate_string
		)) {
			key->truncated |= CTAP_truncated_userName;
		}
	} else {
		ctap_set_absent(&key->user, CTAP_userEntity_name);
	}
	if (ctap_param_is_present(updated_user, CTAP_userEntity_displayName) && updated_user->displayName.size > 0) {
		ctap_set_present(&key->user, CTAP_userEntity_displayName);
		if (ctap_store_arbitrary_length_string(
			&updated_user->displayName,
			&key->user.displayName,
			key->userDisplayName_buffer,
			sizeof(key->userDisplayName_buffer),
			ctap_maybe_truncate_string
		)) {
			key->truncated |= CTAP_truncated_userDisplayName;
		}
	} else {
		ctap_set_absent(&key->user, CTAP_userEntity_displayName);
	}

	return CTAP2_OK;

}

uint8_t ctap_credential_management(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	uint8_t ret;

	CTAP_credentialManagement cm;
	ctap_check(ctap_parse_credential_management(it, &cm));

	// 6.8. authenticatorCredentialManagement (0x0A)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement

	// common steps for all subcommands

	if (!ctap_param_is_present(&cm, CTAP_credentialManagement_subCommand)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	const bool pinUvAuthParamRequired =
		cm.subCommand != CTAP_credentialManagement_subCmd_enumerateRPsGetNextRP
		&& cm.subCommand != CTAP_credentialManagement_subCmd_enumerateCredentialsGetNextCredential;
	if (pinUvAuthParamRequired) {
		if (!ctap_param_is_present(&cm, CTAP_credentialManagement_pinUvAuthParam)) {
			return CTAP2_ERR_PUAT_REQUIRED;
		}
		if (!ctap_param_is_present(&cm, CTAP_credentialManagement_pinUvAuthProtocol)) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		ctap_pin_protocol_t *pin_protocol;
		// if the given pinUvAuthProtocol is not supported, it returns CTAP1_ERR_INVALID_PARAMETER
		ctap_check(ctap_get_pin_protocol(state, cm.pinUvAuthProtocol, &pin_protocol));
		// Authenticator calls verify(pinUvAuthToken, subCommand || subCommandParams, pinUvAuthParam)
		ctap_check(verify_credential_management_params(state, &cm, pin_protocol));
	}

	switch (cm.subCommand) {

		case CTAP_credentialManagement_subCmd_getCredsMetadata:
			debug_log(magenta("CTAP_credentialManagement_subCmd_getCredsMetadata") nl);
			return credential_management_get_creds_metadata(state, encoder);

		case CTAP_credentialManagement_subCmd_enumerateRPsBegin:
			debug_log(magenta("CTAP_credentialManagement_subCmd_enumerateRPsBegin") nl);
			return credential_management_enumerate_rps_begin(state, encoder);

		case CTAP_credentialManagement_subCmd_enumerateRPsGetNextRP:
			debug_log(magenta("CTAP_credentialManagement_subCmd_enumerateRPsGetNextRP") nl);
			return credential_management_enumerate_rps_get_next_rp(state, encoder);

		case CTAP_credentialManagement_subCmd_enumerateCredentialsBegin:
			debug_log(magenta("CTAP_credentialManagement_subCmd_enumerateCredentialsBegin") nl);
			return credential_management_enumerate_credentials_begin(state, &cm, encoder);

		case CTAP_credentialManagement_subCmd_enumerateCredentialsGetNextCredential:
			debug_log(magenta("CTAP_credentialManagement_subCmd_enumerateCredentialsGetNextCredential") nl);
			return credential_management_enumerate_credentials_get_next_credential(state, encoder);

		case CTAP_credentialManagement_subCmd_deleteCredential:
			debug_log(magenta("CTAP_credentialManagement_subCmd_deleteCredential") nl);
			return credential_management_delete_credential(state, &cm);

		case CTAP_credentialManagement_subCmd_updateUserInformation:
			debug_log(magenta("CTAP_credentialManagement_subCmd_updateUserInformation") nl);
			return credential_management_update_user_information(state, &cm);

	}

	// default case (unknown or unsupported subcommand)
	return CTAP2_ERR_INVALID_SUBCOMMAND;

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
