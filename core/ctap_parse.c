#include "ctap_parse.h"
#include <cbor.h>

// TODO: test
static inline CborError ctap_cbor_value_get_uint8(const CborValue *value, uint8_t *result) {
	assert(cbor_value_is_unsigned_integer(value));
	if (value->flags & CborIteratorFlag_IntegerValueTooLarge) {
		return CborErrorDataTooLarge;
	}
	// TODO: add unlikely
	if (value->extra > UINT8_MAX) {
		return CborErrorDataTooLarge;
	}
	*result = (uint8_t) value->extra;
	return CborNoError;
}

#define ctap_parse_map_enter(name) \
    uint8_t ret; \
    CborError err; \
    CborValue map; \
    size_t map_length; \
    ctap_cbor_ensure_type(cbor_value_is_map(it)); \
    cbor_decoding_check(cbor_value_enter_container(it, &map)); \
    cbor_decoding_check(cbor_value_get_map_length(it, &map_length)); \
    debug_log(name " map_length=%" PRIsz nl, map_length)

#define ctap_parse_map_leave() \
    cbor_decoding_check(cbor_value_leave_container(it, &map))

#define ctap_parse_map_get_string_key() \
    ctap_string_t key; \
    ctap_check(parse_text_string_to_ctap_string(&map, &key))

#define ctap_parse_map_get_int_key() \
    int key; \
    ctap_cbor_ensure_type(cbor_value_is_integer(&map)); \
    cbor_decoding_check(cbor_value_get_int_checked(&map, &key)); \
    cbor_decoding_check(cbor_value_advance_fixed(&map))

static uint8_t parse_uint8(
	CborValue *it,
	uint8_t *result
) {

	CborError err;

	ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(it));
	cbor_decoding_check(ctap_cbor_value_get_uint8(it, result));
	cbor_decoding_check(cbor_value_advance_fixed(it));

	return CTAP2_OK;

}

static uint8_t parse_byte_string_to_ctap_string(
	CborValue *it,
	ctap_string_t *string
) {

	CborError err;

	ctap_cbor_ensure_type(cbor_value_is_byte_string(it));

	// CTAP2 canonical CBOR encoding form requires all strings to be definite-length strings.
	if (!cbor_value_is_length_known(it)) {
		debug_log(red("CTAP2_ERR_INVALID_CBOR: an indefinite-length byte string") nl);
		return CTAP2_ERR_INVALID_CBOR;
	}

	// We use the cbor_value_get_text_string_chunk() API to avoid unnecessary copying
	// (i.e., just get the pointer to the string within the CBOR data).
	// Note:
	//   TinyCBOR offers the same consistent API for both indefinite-length strings (i.e., chunked strings)
	//   and definite-length strings (which are not chunked, but TinyCBOR API treats them as single-chunk strings).

	// TinyCBOR API treats definite-length strings as single-chunk strings.
	cbor_decoding_check(cbor_value_begin_string_iteration(it));
	cbor_decoding_check(cbor_value_get_byte_string_chunk(it, &string->data, &string->size, it));
	assert(string->data != NULL);
	cbor_decoding_check(cbor_value_finish_string_iteration(it));

	return CTAP2_OK;

}

static uint8_t parse_text_string_to_ctap_string(
	CborValue *it,
	ctap_string_t *string
) {

	CborError err;

	ctap_cbor_ensure_type(cbor_value_is_text_string(it));

	// CTAP2 canonical CBOR encoding form requires all strings to be definite-length strings.
	if (!cbor_value_is_length_known(it)) {
		debug_log(red("CTAP2_ERR_INVALID_CBOR: an indefinite-length text string") nl);
		return CTAP2_ERR_INVALID_CBOR;
	}

	// We use the cbor_value_get_text_string_chunk() API to avoid unnecessary copying
	// (i.e., just get the pointer to the string within the CBOR data).
	// Note:
	//   TinyCBOR offers the same consistent API for both indefinite-length strings (i.e., chunked strings)
	//   and definite-length strings (which are not chunked, but TinyCBOR API treats them as single-chunk strings).

	// TinyCBOR API treats definite-length strings as single-chunk strings.
	cbor_decoding_check(cbor_value_begin_string_iteration(it));
	cbor_decoding_check(cbor_value_get_text_string_chunk(it, (const char **) &string->data, &string->size, it));
	assert(string->data != NULL);
	cbor_decoding_check(cbor_value_finish_string_iteration(it));

	return CTAP2_OK;

}

static uint8_t parse_copy_fixed_byte_string(
	CborValue *it,
	uint8_t *buffer,
	const size_t expected_length
) {

	uint8_t ret;

	ctap_string_t byte_string;

	ctap_check(parse_byte_string_to_ctap_string(it, &byte_string));

	if (byte_string.size != expected_length) {
		error_log(
			"parse_copy_fixed_byte_string: invalid length: actual %" PRIsz " < expected %" PRIsz nl,
			byte_string.size, expected_length
		);
		// 8. Message Encoding, CTAP2 canonical CBOR encoding form
		// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form
		// If structures in messages from the host are missing required members,
		// or the values of those members have the wrong type,
		// then the authenticator SHOULD return CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	memcpy(buffer, byte_string.data, expected_length);

	return CTAP2_OK;

}

static uint8_t parse_cose_key(CborValue *it, COSE_Key *cose_key) {

	ctap_parse_map_enter("COSE_Key");

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case COSE_Key_label_kty:
				debug_log("COSE_Key_label_kty" nl);
				ctap_cbor_ensure_type(cbor_value_is_integer(&map));
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose_key->kty));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(cose_key, COSE_Key_field_kty);
				break;

			case COSE_Key_label_alg:
				debug_log("COSE_Key_label_alg" nl);
				ctap_cbor_ensure_type(cbor_value_is_integer(&map));
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose_key->alg));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(cose_key, COSE_Key_field_alg);
				break;

			case COSE_Key_kty_OKP_EC2_label_crv:
				debug_log("COSE_Key_kty_OKP_EC2_label_crv" nl);
				ctap_cbor_ensure_type(cbor_value_is_integer(&map));
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose_key->crv));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(cose_key, COSE_Key_field_crv);
				break;

			case COSE_Key_kty_OKP_EC2_label_x:
				debug_log("COSE_Key_kty_OKP_EC2_label_x" nl);
				ctap_check(parse_copy_fixed_byte_string(&map, cose_key->pubkey.x, 32));
				ctap_set_present(cose_key, COSE_Key_field_pubkey_x);
				break;

			case COSE_Key_kty_OKP_EC2_label_y:
				debug_log("COSE_Key_kty_OKP_EC2_label_y" nl);
				ctap_check(parse_copy_fixed_byte_string(&map, cose_key->pubkey.y, 32));
				ctap_set_present(cose_key, COSE_Key_field_pubkey_y);
				break;

			default:
				debug_log("warning: unrecognized cose key option %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present

	if (!ctap_param_is_present(cose_key, COSE_Key_field_kty)) {
		// https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-common-parameters
		// kty: This parameter MUST be present in a key object.
		debug_log(red("parse_cose_key: missing kty") nl);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	if (cose_key->kty == COSE_Key_kty_EC2) {
		// https://datatracker.ietf.org/doc/html/rfc9053#name-double-coordinate-curves
		// For public keys, it is REQUIRED that "crv", "x", and "y" be present in the structure.
		const uint32_t required_params =
			ctap_param_to_mask(COSE_Key_field_crv)
			// alg is optional
			| ctap_param_to_mask(COSE_Key_field_pubkey_x)
			| ctap_param_to_mask(COSE_Key_field_pubkey_y);
		if (!ctap_is_present(cose_key->present, required_params)) {
			debug_log(
				red(
					"parse_cose_key: kty EC2 missing some of the required params (crv, x, y)"
					" present=%" PRIu32 " required=%" PRIu32
			) nl,
				cose_key->present, required_params
			);
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		return CTAP2_OK;
	}

	// other key types are not supported yet
	debug_log(red("parse_cose_key: unsupported kty value %d") nl, cose_key->kty);
	return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

}

static uint8_t parse_pin_uv_auth_protocol_public_key(CborValue *it, COSE_Key *cose_key) {

	uint8_t ret;

	// 6.5.6. PIN/UV Auth Protocol One
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#puap1keyagmnt-key-agreement-key
	// getPublicKey()
	//   getPublicKey() returns a COSE_Key with the following header parameters:
	//     1 (kty) = 2 (EC2)
	//     3 (alg) = -25 (although this is not the algorithm actually used)
	//     -1 (crv) = 1 (P-256)
	//     -2 (x) = 32-byte, big-endian encoding of the x-coordinate of xB (the key agreement key's public point)
	//     -3 (y) = 32-byte, big-endian encoding of the y-coordinate of xB

	// parse_cose_key() ensures kty == 2 (EC2) and the presence of the crv, x, y fields
	ctap_check(parse_cose_key(it, cose_key));

	if (!ctap_param_is_present(cose_key, COSE_Key_field_alg)) {
		debug_log(red("parse_pin_uv_auth_protocol_public_key: missing alg") nl);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}
	if (cose_key->alg != COSE_ALG_ECDH_ES_HKDF_256) {
		debug_log(
			red("parse_pin_uv_auth_protocol_public_key: invalid alg value %d, expected %d") nl,
			cose_key->alg, COSE_ALG_ECDH_ES_HKDF_256
		);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}
	if (cose_key->crv != COSE_Key_kty_EC2_crv_P256) {
		debug_log(
			red("parse_pin_uv_auth_protocol_public_key: invalid crv value %d, expected %d") nl,
			cose_key->crv, COSE_Key_kty_EC2_crv_P256
		);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	return CTAP2_OK;

}

uint8_t ctap_parse_client_pin(CborValue *it, CTAP_clientPIN *params) {

	ctap_parse_map_enter("authenticatorClientPin parameters");

	memset(params, 0, sizeof(CTAP_clientPIN));

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_clientPIN_pinUvAuthProtocol:
				debug_log("CTAP_clientPIN_pinUvAuthProtocol" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_clientPIN_pinUvAuthProtocol);
				break;

			case CTAP_clientPIN_subCommand:
				debug_log("CTAP_clientPIN_subCommand" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->subCommand));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_clientPIN_subCommand);
				break;

			case CTAP_clientPIN_keyAgreement:
				debug_log("CTAP_clientPIN_keyAgreement" nl);
				ctap_check(parse_pin_uv_auth_protocol_public_key(&map, &params->keyAgreement));
				ctap_set_present(params, CTAP_clientPIN_keyAgreement);
				break;

			case CTAP_clientPIN_pinUvAuthParam:
				debug_log("CTAP_clientPIN_pinUvAuthParam" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->pinUvAuthParam));
				ctap_set_present(params, CTAP_clientPIN_pinUvAuthParam);
				break;

			case CTAP_clientPIN_newPinEnc:
				debug_log("CTAP_clientPIN_newPinEnc" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->newPinEnc));
				ctap_set_present(params, CTAP_clientPIN_newPinEnc);
				break;

			case CTAP_clientPIN_pinHashEnc:
				debug_log("CTAP_clientPIN_pinHashEnc" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->pinHashEnc));
				ctap_set_present(params, CTAP_clientPIN_pinHashEnc);
				break;

			case CTAP_clientPIN_permissions:
				debug_log("CTAP_clientPIN_permissions" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				uint64_t permissions;
				cbor_decoding_check(cbor_value_get_uint64(&map, &permissions));
				ctap_cbor_ensure_type(permissions <= UINT32_MAX);
				params->permissions = (uint32_t) permissions;
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_clientPIN_permissions);
				break;

			case CTAP_clientPIN_rpId:
				debug_log("CTAP_clientPIN_rpId" nl);
				ctap_check(parse_text_string_to_ctap_string(&map, &params->rpId));
				debug_log(
					"CTAP_clientPIN_rpId rpId (%" PRIsz ") = '%.*s'" nl,
					params->rpId.size, (int) params->rpId.size, params->rpId.data
				);
				ctap_set_present(params, CTAP_clientPIN_rpId);
				break;

			default:
				debug_log("ctap_parse_client_pin: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	if (!ctap_is_present(params->present, ctap_param_to_mask(CTAP_clientPIN_subCommand))) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

static uint8_t parse_rp_entity(CborValue *it, CTAP_rpId *rpId) {

	ctap_parse_map_enter("PublicKeyCredentialRpEntity");

	bool id_parsed = false;

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("id"))) {
			ctap_check(parse_text_string_to_ctap_string(&map, rpId));
			id_parsed = true;
		} else {
			// Currently, we do not use name and icon in any way, but we at least validate their types
			// for compliance reasons (FIDO Conformance Tools checks this).
			if (ctap_string_matches(&key, &ctap_str("name"))) {
				ctap_cbor_ensure_type(cbor_value_is_text_string(&map));
			} else if (ctap_string_matches(&key, &ctap_str("icon"))) {
				ctap_cbor_ensure_type(cbor_value_is_byte_string(&map));
			} else {
				debug_log("warning: unrecognized PublicKeyCredentialRpEntity key %.*s" nl, (int) key.size, key.data);
			}
			// important: skip over the unused value
			cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	if (!id_parsed) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

static uint8_t parse_user_entity(CborValue *it, CTAP_userEntity *user) {

	ctap_parse_map_enter("PublicKeyCredentialUserEntity");

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("id"))) {
			ctap_check(parse_byte_string_to_ctap_string(&map, &user->id));
			// The WebAuthn spec defines a maximum size of 64 bytes for the userHandle (user.id).
			if (user->id.size > CTAP_USER_ENTITY_ID_MAX_SIZE) {
				debug_log(
					red("exceeded user handle (user.id) max size (%" PRIsz " > %" PRIsz ")") nl,
					user->id.size, (size_t) CTAP_USER_ENTITY_ID_MAX_SIZE
				);
				return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
			}
			ctap_set_present(user, CTAP_userEntity_id);
		} else if (ctap_string_matches(&key, &ctap_str("name"))) {
			ctap_check(parse_text_string_to_ctap_string(&map, &user->name));
			ctap_set_present(user, CTAP_userEntity_name);
		} else if (ctap_string_matches(&key, &ctap_str("displayName"))) {
			ctap_check(parse_text_string_to_ctap_string(&map, &user->displayName));
			ctap_set_present(user, CTAP_userEntity_displayName);
		} else {
			// Currently, we do not use icon in any way, but we at least validate its type
			// for compliance reasons (FIDO Conformance Tools checks this).
			if (ctap_string_matches(&key, &ctap_str("icon"))) {
				ctap_cbor_ensure_type(cbor_value_is_byte_string(&map));
			} else {
				debug_log("warning: unrecognized PublicKeyCredentialUserEntity key %.*s" nl, (int) key.size, key.data);
			}
			// important: skip over the unused value
			cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	const uint32_t required_params = ctap_param_to_mask(CTAP_userEntity_id);
	if (!ctap_is_present(user->present, required_params)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	return CTAP2_OK;

}

static uint8_t parse_mc_ga_options(
	CborValue *it,
	CTAP_mc_ga_options *options
) {

	ctap_parse_map_enter("parse_mc_ga_options");

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		uint8_t option;
		bool value;

		// Note:
		//   The rk option is only applicable for authenticatorMakeCredential.
		//   The spec says: Platforms MUST NOT send the "rk" option key.
		if (ctap_string_matches(&key, &ctap_str("rk"))) {
			option = CTAP_ma_ga_option_rk;
		} else if (ctap_string_matches(&key, &ctap_str("up"))) {
			option = CTAP_ma_ga_option_up;
		} else if (ctap_string_matches(&key, &ctap_str("uv"))) {
			option = CTAP_ma_ga_option_uv;
		} else {
			debug_log("warning: unrecognized option key %.*s" nl, (int) key.size, key.data);
			cbor_decoding_check(cbor_value_advance(&map));
			continue;
		}

		ctap_cbor_ensure_type(cbor_value_is_boolean(&map));
		cbor_decoding_check(cbor_value_get_boolean(&map, &value));
		options->present |= option;
		if (value) {
			options->values |= option;
		} // else not needed as we expect the options_values to be zeroed before invoking this function
		cbor_decoding_check(cbor_value_advance_fixed(&map));

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	// nothing to do here

	return CTAP2_OK;

}

static uint8_t parse_make_credential_extensions(CborValue *it, CTAP_makeCredential *mc) {

	CTAP_mc_ga_common *const params = &mc->common;

	ctap_parse_map_enter("parse_make_credential_extensions");

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("credProtect"))) {

			// 12.1. Credential Protection (credProtect)
			// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension

			debug_log("credProtect" nl);
			ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
			cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &mc->credProtect));
			params->extensions_present |= CTAP_extension_credProtect;
			cbor_decoding_check(cbor_value_advance_fixed(&map));

		} else if (ctap_string_matches(&key, &ctap_str("hmac-secret"))) {

			// 12.5. HMAC Secret Extension (hmac-secret)
			// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension

			debug_log("hmac-secret" nl);
			ctap_cbor_ensure_type(cbor_value_is_boolean(&map));
			bool value;
			cbor_decoding_check(cbor_value_get_boolean(&map, &value));
			if (value) {
				// The client should always either send hmac-secret: true or nothing at all
				// ((hmac-secret: false) should never be sent).
				params->extensions_present |= CTAP_extension_hmac_secret;
			} else {
				debug_log(
					"parse_make_credential_extensions: invalid hmac-secret: false, only true allowed, ignoring" nl
				);
			}
			cbor_decoding_check(cbor_value_advance_fixed(&map));

		} else {
			debug_log("warning: unsupported extension %.*s" nl, (int) key.size, key.data);
			cbor_decoding_check(cbor_value_advance(&map));
			continue;
		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	// nothing to do here

	return CTAP2_OK;

}

uint8_t ctap_parse_make_credential(CborValue *it, CTAP_makeCredential *mc) {

	ctap_parse_map_enter("authenticatorMakeCredential parameters");

	memset(mc, 0, sizeof(CTAP_makeCredential));
	CTAP_mc_ga_common *const params = &mc->common;

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_makeCredential_clientDataHash:
				debug_log("CTAP_makeCredential_clientDataHash" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->clientDataHash));
				if (params->clientDataHash.size != CTAP_SHA256_HASH_SIZE) {
					debug_log(red("invalid clientDataHash.size %" PRIsz) nl, params->clientDataHash.size);
					return CTAP1_ERR_INVALID_PARAMETER;
				}
				ctap_set_present(params, CTAP_makeCredential_clientDataHash);
				break;

			case CTAP_makeCredential_rp:
				debug_log("CTAP_makeCredential_rp" nl);
				ctap_check(parse_rp_entity(
					&map,
					&params->rpId
				));
				ctap_set_present(params, CTAP_makeCredential_rp);
				break;

			case CTAP_makeCredential_user:
				debug_log("CTAP_makeCredential_user" nl);
				ctap_check(parse_user_entity(
					&map,
					&mc->user
				));
				ctap_set_present(params, CTAP_makeCredential_user);
				break;

			case CTAP_makeCredential_pubKeyCredParams:
				debug_log("CTAP_makeCredential_pubKeyCredParams" nl);
				ctap_cbor_ensure_type(cbor_value_is_array(&map));
				mc->pubKeyCredParams = map;
				cbor_decoding_check(cbor_value_advance(&map));
				ctap_set_present(params, CTAP_makeCredential_pubKeyCredParams);
				break;

			case CTAP_makeCredential_excludeList:
				debug_log("CTAP_makeCredential_excludeList" nl);
				ctap_cbor_ensure_type(cbor_value_is_array(&map));
				mc->excludeList = map;
				cbor_decoding_check(cbor_value_advance(&map));
				ctap_set_present(params, CTAP_makeCredential_excludeList);
				break;

			case CTAP_makeCredential_extensions:
				debug_log("CTAP_makeCredential_extensions" nl);
				ctap_check(parse_make_credential_extensions(&map, mc));
				ctap_set_present(params, CTAP_makeCredential_extensions);
				break;

			case CTAP_makeCredential_options:
				debug_log("CTAP_makeCredential_options" nl);
				ctap_check(parse_mc_ga_options(&map, &params->options));
				ctap_set_present(params, CTAP_makeCredential_options);
				break;

			case CTAP_makeCredential_pinUvAuthParam:
				debug_log("CTAP_makeCredential_pinUvAuthParam" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->pinUvAuthParam));
				ctap_set_present(params, CTAP_makeCredential_pinUvAuthParam);
				break;

			case CTAP_makeCredential_pinUvAuthProtocol:
				debug_log("CTAP_makeCredential_pinUvAuthProtocol" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_makeCredential_pinUvAuthProtocol);
				break;

			case CTAP_makeCredential_enterpriseAttestation:
				debug_log("CTAP_makeCredential_enterpriseAttestation" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				// We don't support the enterprise attestation feature, so we don't need to store the value.
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				// However, we have to store the information that the enterpriseAttestation param is present,
				// so that we can correctly return CTAP1_ERR_INVALID_PARAMETER while processing the command parameters
				// in ctap_make_credential().
				ctap_set_present(params, CTAP_makeCredential_enterpriseAttestation);
				break;

			default:
				debug_log("ctap_parse_make_credential: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	const uint32_t required_params =
		ctap_param_to_mask(CTAP_makeCredential_clientDataHash) |
		ctap_param_to_mask(CTAP_makeCredential_rp) |
		ctap_param_to_mask(CTAP_makeCredential_user) |
		ctap_param_to_mask(CTAP_makeCredential_pubKeyCredParams);
	if (!ctap_is_present(params->present, required_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

static uint8_t parse_cred_params(CborValue *it, CTAP_credParams *cred_params) {

	ctap_parse_map_enter("PublicKeyCredentialParameters");

	bool type_parsed = false;
	bool alg_parsed = false;

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("type"))) {

			char type[10]; // not null terminated
			size_t type_length = sizeof(type);
			ctap_cbor_ensure_type(cbor_value_is_text_string(&map));
			size_t actual_type_length;
			cbor_decoding_check(cbor_value_get_string_length(&map, &actual_type_length));
			if (actual_type_length > type_length) {
				debug_log("parse_cred_params: skipping unknown too long type" nl);
				cbor_decoding_check(cbor_value_advance(&map));
				type_parsed = true;
				continue;
			}
			cbor_decoding_check(cbor_value_copy_text_string(&map, type, &type_length, &map));

			type_parsed = true;

			if (strncmp(type, "public-key", type_length) == 0) {
				cred_params->type = CTAP_pubKeyCredType_public_key;
			}

		} else if (ctap_string_matches(&key, &ctap_str("alg"))) {

			ctap_cbor_ensure_type(cbor_value_is_integer(&map));

			static_assert(
				sizeof(cred_params->alg) >= sizeof(int),
				"cbor_value_get_int_checked cannot be used with cred_params->alg, check sizeof(int)"
			);
			cbor_decoding_check(cbor_value_get_int_checked(&map, (int *) &cred_params->alg));
			alg_parsed = true;
			cbor_decoding_check(cbor_value_advance_fixed(&map));

		} else {
			debug_log("warning: unrecognized PublicKeyCredentialParameters key %.*s" nl, (int) key.size, key.data);
			cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	ctap_parse_map_leave();

	// 6.1.2. authenticatorMakeCredential Algorithm:
	//  3.1.1. If the element is missing required members, including members that are mandatory
	//         only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR
	if (!type_parsed || !alg_parsed) {
		return CTAP2_ERR_INVALID_CBOR;
	}

	return CTAP2_OK;

}

/**
 * NOTE! This function must always be preceded by an invocation of ctap_parse_make_credential()
 *       with the same params argument.
 *
 * This function implements the step 3 from the 6.1.2. authenticatorMakeCredential Algorithm
 * (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg):
 *   3. Validate pubKeyCredParams with the following steps:
 *      1. For each element of pubKeyCredParams:
 *         1. If the element is missing required members, including members that are mandatory
 *            only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR.
 *         2. If the values of any known members have the wrong type then return an error,
 *            for example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
 *         3. If the element specifies an algorithm that is supported by the authenticator,
 *            and no algorithm has yet been chosen by this loop,
 *            then let the algorithm specified by the current element be the chosen algorithm.
 *      2. If the loop completes and no algorithm was chosen
 *         then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
 *     Note: This loop chooses the first occurrence of an algorithm identifier supported
 *     by this authenticator but always iterates over every element of pubKeyCredParams to validate them.
 *
 *
 * @param mc the parsed makeCredential command parameters from ctap_parse_make_credential
 * @returns a CTAP status code (CTAP2_OK on success)
 */
uint8_t ctap_parse_make_credential_pub_key_cred_params(CTAP_makeCredential *mc) {

	uint8_t ret;
	CborError err;
	CborValue array;
	size_t array_length;

	// This should be guaranteed as this function (ctap_parse_make_credential_pub_key_cred_params)
	// should always be called only after ctap_parse_make_credential.
	assert(cbor_value_is_array(&mc->pubKeyCredParams));

	cbor_decoding_check(cbor_value_enter_container(&mc->pubKeyCredParams, &array));
	cbor_decoding_check(cbor_value_get_array_length(&mc->pubKeyCredParams, &array_length));
	debug_log("pubKeyCredParams array_length=%" PRIsz nl, array_length);

	// 6.1.2. authenticatorMakeCredential Algorithm:
	//  3. Note: This loop chooses the first occurrence of an algorithm identifier supported by this authenticator
	//           but always iterates over every element of pubKeyCredParams to validate them.
	bool algorithm_chosen = false;
	for (size_t i = 0; i < array_length; i++) {
		CTAP_credParams cred_params;
		ctap_check(parse_cred_params(&array, &cred_params));
		if (!algorithm_chosen && ctap_is_supported_pub_key_cred_alg(&cred_params)) {
			mc->pubKeyCredParams_chosen = cred_params;
			algorithm_chosen = true;
		}
	}

	// Here we intentionally omit call to cbor_value_leave_container
	// as we do NOT want to update the params->pubKeyCredParams CborValue to point after the array.
	// cbor_decoding_check(cbor_value_leave_container(&params->pubKeyCredParams, &array));

	// 6.1.2. authenticatorMakeCredential Algorithm:
	//  3.2. If the loop completes and no algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM.
	if (!algorithm_chosen) {
		return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
	}

	return CTAP2_OK;

}

static uint8_t parse_cred_desc(CborValue *it, CTAP_credDesc *cred_desc) {

	ctap_parse_map_enter("PublicKeyCredentialDescriptor");

	bool type_parsed = false;
	bool id_parsed = false;

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("type"))) {

			ctap_string_t type;
			ctap_check(parse_text_string_to_ctap_string(&map, &type));

			type_parsed = true;

			if (ctap_string_matches(&type, &ctap_str("public-key"))) {
				cred_desc->type = CTAP_pubKeyCredType_public_key;
			} else {
				cred_desc->type = 0;
			}

		} else if (ctap_string_matches(&key, &ctap_str("id"))) {

			ctap_check(parse_byte_string_to_ctap_string(&map, &cred_desc->id));
			id_parsed = true;

		} else {
			debug_log("warning: unrecognized PublicKeyCredentialParameters key %.*s" nl, (int) key.size, key.data);
			cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	if (!type_parsed || !id_parsed) {
		return CTAP2_ERR_INVALID_CBOR;
	}

	return CTAP2_OK;

}

uint8_t ctap_parse_pub_key_cred_desc_list_init(
	ctap_parse_pub_key_cred_desc_list_ctx *ctx,
	const CborValue *list
) {

	CborError err;

	// This should be guaranteed as this function (ctap_parse_pub_key_cred_desc_list_init)
	// should always be called only after ctap_parse_make_credential / ctap_parse_get_assertion.
	ctap_cbor_ensure_type(cbor_value_is_array(list));

	cbor_decoding_check(cbor_value_enter_container(list, &ctx->it));
	cbor_decoding_check(cbor_value_get_array_length(list, &ctx->length));
	debug_log("pub_key_cred_desc_list length=%" PRIsz nl, ctx->length);
	ctx->next_idx = 0;

	return CTAP2_OK;

}

uint8_t ctap_parse_pub_key_cred_desc_list_next_cred(
	ctap_parse_pub_key_cred_desc_list_ctx *ctx,
	CTAP_credDesc **cred_desc
) {

	uint8_t ret;

	if (ctx->next_idx == ctx->length) {
		*cred_desc = NULL;
		return CTAP2_OK;
	}

	ctap_check(parse_cred_desc(&ctx->it, &ctx->item));
	ctx->next_idx++;
	*cred_desc = &ctx->item;
	return CTAP2_OK;

}

static uint8_t parse_get_assertion_hmac_secret_extension(CborValue *it, CTAP_getAssertion_hmac_secret *params) {

	ctap_parse_map_enter("authenticatorGetAssertion hmac-secret extension");

	// 12.5. HMAC Secret Extension (hmac-secret), authenticatorGetAssertion additional behaviors
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_getAssertion_hmac_secret_keyAgreement:
				debug_log("CTAP_getAssertion_hmac_secret_keyAgreement" nl);
				ctap_check(parse_pin_uv_auth_protocol_public_key(&map, &params->keyAgreement));
				ctap_set_present(params, CTAP_getAssertion_hmac_secret_keyAgreement);
				break;

			case CTAP_getAssertion_hmac_secret_saltEnc:
				debug_log("CTAP_getAssertion_hmac_secret_saltEnc" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->saltEnc));
				ctap_set_present(params, CTAP_getAssertion_hmac_secret_saltEnc);
				break;

			case CTAP_getAssertion_hmac_secret_saltAuth:
				debug_log("CTAP_getAssertion_hmac_secret_saltAuth" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->saltAuth));
				ctap_set_present(params, CTAP_getAssertion_hmac_secret_saltAuth);
				break;

			case CTAP_getAssertion_hmac_secret_pinUvAuthProtocol:
				debug_log("CTAP_getAssertion_hmac_secret_pinUvAuthProtocol" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_getAssertion_hmac_secret_pinUvAuthProtocol);
				break;

			default:
				debug_log("parse_get_assertion_hmac_secret_extension: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	// (everything is optional)

	return CTAP2_OK;

}

static uint8_t parse_get_assertion_extensions(CborValue *it, CTAP_getAssertion *ga) {

	CTAP_mc_ga_common *const params = &ga->common;

	ctap_parse_map_enter("parse_get_assertion_extensions");

	for (size_t i = 0; i < map_length; ++i) {

		ctap_parse_map_get_string_key();

		if (ctap_string_matches(&key, &ctap_str("hmac-secret"))) {

			ctap_check(parse_get_assertion_hmac_secret_extension(it, &ga->hmac_secret));
			params->extensions_present |= CTAP_extension_hmac_secret;

		} else {

			debug_log("warning: unsupported extension %.*s" nl, (int) key.size, key.data);
			cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	// nothing to do here

	return CTAP2_OK;

}

uint8_t ctap_parse_get_assertion(CborValue *it, CTAP_getAssertion *ga) {

	ctap_parse_map_enter("authenticatorGetAssertion parameters");

	memset(ga, 0, sizeof(CTAP_getAssertion));
	CTAP_mc_ga_common *const params = &ga->common;

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_getAssertion_rpId:
				debug_log("CTAP_getAssertion_rpId" nl);
				ctap_check(parse_text_string_to_ctap_string(&map, &params->rpId));
				debug_log(
					"CTAP_getAssertion_rpId rpId (%" PRIsz ") = '%.*s'" nl,
					params->rpId.size, (int) params->rpId.size, params->rpId.data
				);
				ctap_set_present(params, CTAP_getAssertion_rpId);
				break;

			case CTAP_getAssertion_clientDataHash:
				debug_log("CTAP_getAssertion_clientDataHash" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->clientDataHash));
				ctap_set_present(params, CTAP_getAssertion_clientDataHash);
				break;

			case CTAP_getAssertion_allowList:
				debug_log("CTAP_getAssertion_allowList" nl);
				ctap_cbor_ensure_type(cbor_value_is_array(&map));
				ga->allowList = map;
				cbor_decoding_check(cbor_value_advance(&map));
				ctap_set_present(params, CTAP_getAssertion_allowList);
				break;

			case CTAP_getAssertion_extensions:
				debug_log("CTAP_getAssertion_extensions" nl);
				ctap_check(parse_get_assertion_extensions(&map, ga));
				ctap_set_present(params, CTAP_getAssertion_extensions);
				break;

			case CTAP_getAssertion_options:
				debug_log("CTAP_getAssertion_options" nl);
				ctap_check(parse_mc_ga_options(&map, &params->options));
				ctap_set_present(params, CTAP_getAssertion_options);
				break;

			case CTAP_getAssertion_pinUvAuthParam:
				debug_log("CTAP_getAssertion_pinUvAuthParam" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->pinUvAuthParam));
				ctap_set_present(params, CTAP_getAssertion_pinUvAuthParam);
				break;

			case CTAP_getAssertion_pinUvAuthProtocol:
				debug_log("CTAP_getAssertion_pinUvAuthProtocol" nl);
				ctap_cbor_ensure_type(cbor_value_is_unsigned_integer(&map));
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_getAssertion_pinUvAuthProtocol);
				break;

			default:
				debug_log("ctap_parse_get_assertion: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	const uint32_t required_params =
		ctap_param_to_mask(CTAP_getAssertion_rpId) |
		ctap_param_to_mask(CTAP_getAssertion_clientDataHash);
	if (!ctap_is_present(params->present, required_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

static uint8_t parse_credential_management_subcommand_params(CborValue *it, CTAP_credentialManagement_subCmdParams *params) {

	ctap_parse_map_enter("authenticatorCredentialManagement subCommandParams");

	params->raw = it->source.ptr;

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_credentialManagement_subCommandParams_rpIDHash:
				debug_log("CTAP_credentialManagement_subCommandParams_rpIDHash" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &params->rpIDHash));
				if (params->rpIDHash.size != CTAP_SHA256_HASH_SIZE) {
					debug_log(red("invalid rpIDHash.size %" PRIsz) nl, params->rpIDHash.size);
					return CTAP1_ERR_INVALID_PARAMETER;
				}
				ctap_set_present(params, CTAP_credentialManagement_subCommandParams_rpIDHash);
				break;

			case CTAP_credentialManagement_subCommandParams_credentialID:
				debug_log("CTAP_credentialManagement_subCommandParams_credentialID" nl);
				ctap_check(parse_cred_desc(&map, &params->credentialID));
				ctap_set_present(params, CTAP_credentialManagement_subCommandParams_credentialID);
				break;

			case CTAP_credentialManagement_subCommandParams_user:
				debug_log("CTAP_credentialManagement_subCommandParams_user" nl);
				ctap_check(parse_user_entity(&map, &params->user));
				ctap_set_present(params, CTAP_credentialManagement_subCommandParams_user);
				break;

			default:
				debug_log("ctap_parse_credential_management: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	params->raw_size = it->source.ptr - params->raw;
	assert(params->raw_size > 0); // even a map with zero key-value pairs is 1 byte (0xa0)

	// validate: check that all required parameters are present
	// (nothing to do, everything is optional at this point)

	return CTAP2_OK;

}

uint8_t ctap_parse_credential_management(CborValue *it, CTAP_credentialManagement *cm) {

	ctap_parse_map_enter("authenticatorCredentialManagement parameters");

	memset(cm, 0, sizeof(CTAP_credentialManagement));

	for (size_t i = 0; i < map_length; i++) {

		ctap_parse_map_get_int_key();

		switch (key) {

			case CTAP_credentialManagement_subCommand:
				debug_log("CTAP_credentialManagement_subCommand" nl);
				ctap_check(parse_uint8(&map, &cm->subCommand));
				ctap_set_present(cm, CTAP_credentialManagement_subCommand);
				break;

			case CTAP_credentialManagement_subCommandParams:
				debug_log("CTAP_credentialManagement_subCommandParams" nl);
				ctap_check(parse_credential_management_subcommand_params(&map, &cm->subCommandParams));
				ctap_set_present(cm, CTAP_credentialManagement_subCommandParams);
				break;

			case CTAP_credentialManagement_pinUvAuthProtocol:
				debug_log("CTAP_credentialManagement_pinUvAuthProtocol" nl);
				ctap_check(parse_uint8(&map, &cm->pinUvAuthProtocol));
				ctap_set_present(cm, CTAP_credentialManagement_pinUvAuthProtocol);
				break;

			case CTAP_credentialManagement_pinUvAuthParam:
				debug_log("CTAP_credentialManagement_pinUvAuthParam" nl);
				ctap_check(parse_byte_string_to_ctap_string(&map, &cm->pinUvAuthParam));
				ctap_set_present(cm, CTAP_credentialManagement_pinUvAuthParam);
				break;

			default:
				debug_log("ctap_parse_credential_management: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate: check that all required parameters are present
	const uint32_t required_params =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand);
	if (!ctap_is_present(cm->present, required_params)) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}
