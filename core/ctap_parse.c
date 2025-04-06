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
    if (!cbor_value_is_map(it)) { \
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; \
    } \
    cbor_decoding_check(cbor_value_enter_container(it, &map)); \
    cbor_decoding_check(cbor_value_get_map_length(it, &map_length)); \
    debug_log(name " map_length=%" PRIsz nl, map_length)

#define ctap_parse_map_leave() \
    cbor_decoding_check(cbor_value_leave_container(it, &map))

static uint8_t parse_fixed_byte_string(
	const CborValue *value,
	uint8_t *buffer,
	size_t expected_length,
	CborValue *next
) {

	CborError err;

	if (!cbor_value_is_byte_string(value)) {
		error_log("parse_fixed_byte_string: not a byte string" nl);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	size_t length = expected_length;
	// If the byte string does not fit into the buffer of the given length
	// the cbor_value_copy_byte_string returns an error and does NOT update the length value.
	cbor_decoding_check(cbor_value_copy_byte_string(value, buffer, &length, next));
	// On success, the cbor_value_copy_byte_string updates the length value to the number
	// of bytes copied to the buffer. From the described contract, it is clear that the following must hold:
	// length <= expected_length
	assert(length <= expected_length);
	if (length != expected_length) {
		error_log(
			"parse_fixed_byte_string: invalid length: actual %" PRIsz " < expected %" PRIsz nl,
			length, expected_length
		);
		return CTAP1_ERR_INVALID_LENGTH; // TODO: Use CTAP2_ERR_CBOR_UNEXPECTED_TYPE?
	}

	return CTAP2_OK;

}

static uint8_t parse_byte_string(
	const CborValue *value,
	uint8_t *buffer,
	size_t *length,
	size_t min_length,
	size_t max_length,
	CborValue *next
) {

	assert(min_length <= max_length);

	CborError err;

	if (!cbor_value_is_byte_string(value)) {
		error_log("parse_byte_string: not a byte string" nl);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	size_t actual_length;
	cbor_decoding_check(cbor_value_get_string_length(value, &actual_length));
	if (actual_length > max_length || actual_length < min_length) {
		return CTAP1_ERR_INVALID_LENGTH; // TODO: Use CTAP2_ERR_CBOR_UNEXPECTED_TYPE?
	}

	*length = actual_length;
	cbor_decoding_check(cbor_value_copy_byte_string(value, buffer, length, next));
	assert(*length == actual_length);

	return CTAP2_OK;

}

static uint8_t parse_text_string(
	const CborValue *value,
	uint8_t *buffer,
	size_t *length,
	size_t min_length,
	size_t max_length,
	CborValue *next
) {

	assert(min_length <= max_length);

	CborError err;

	if (!cbor_value_is_text_string(value)) {
		error_log("parse_text_string: not a text string" nl);
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	size_t actual_length;
	cbor_decoding_check(cbor_value_get_string_length(value, &actual_length));
	if (actual_length > max_length || actual_length < min_length) {
		return CTAP1_ERR_INVALID_LENGTH; // TODO: Use CTAP2_ERR_CBOR_UNEXPECTED_TYPE?
	}

	*length = actual_length;
	cbor_decoding_check(cbor_value_copy_text_string(value, (char *) buffer, length, next));
	assert(*length == actual_length);

	return CTAP2_OK;

}

static uint8_t parse_cose_key(CborValue *it, COSE_Key *cose) {

	ctap_parse_map_enter("COSE_Key");

	bool pubkey_x_parsed = false;
	bool pubkey_y_parsed = false;
	cose->kty = 0;
	cose->crv = 0;

	for (size_t i = 0; i < map_length; i++) {

		int key;
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		cbor_decoding_check(cbor_value_advance_fixed(&map));

		switch (key) {

			case COSE_KEY_LABEL_KTY:
				debug_log("COSE_KEY_LABEL_KTY" nl);
				if (!cbor_value_is_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose->kty));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;

			case COSE_KEY_LABEL_ALG:
				debug_log("COSE_KEY_LABEL_ALG" nl);
				if (!cbor_value_is_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				int alg;
				cbor_decoding_check(cbor_value_get_int_checked(&map, &alg));
				// 6.5.6.
				// getPublicKey()
				// 3 (alg) = -25 (although this is not the algorithm actually used)
				if (alg != COSE_ALG_ECDH_ES_HKDF_256) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;

			case COSE_KEY_LABEL_CRV:
				debug_log("COSE_KEY_LABEL_CRV" nl);
				if (!cbor_value_is_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose->crv));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;

			case COSE_KEY_LABEL_X:
				debug_log("COSE_KEY_LABEL_X" nl);
				ctap_parse_check(parse_fixed_byte_string(&map, cose->pubkey.x, 32, &map));
				pubkey_x_parsed = true;
				break;

			case COSE_KEY_LABEL_Y:
				debug_log("COSE_KEY_LABEL_Y" nl);
				ctap_parse_check(parse_fixed_byte_string(&map, cose->pubkey.y, 32, &map));
				pubkey_y_parsed = true;
				break;

			default:
				debug_log("warning: unrecognized cose key option %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));

		}

	}

	ctap_parse_map_leave();

	// validate
	if (pubkey_x_parsed == 0 || pubkey_y_parsed == 0 || cose->kty == 0 || cose->crv == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

uint8_t ctap_parse_client_pin(CborValue *it, CTAP_clientPIN *params) {

	ctap_parse_map_enter("authenticatorClientPin parameters");

	memset(params, 0, sizeof(CTAP_clientPIN));

	for (size_t i = 0; i < map_length; i++) {

		int key;
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		cbor_decoding_check(cbor_value_advance_fixed(&map));

		switch (key) {

			case CTAP_clientPIN_pinUvAuthProtocol:
				debug_log("CTAP_clientPIN_pinUvAuthProtocol" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_clientPIN_pinUvAuthProtocol);
				break;

			case CTAP_clientPIN_subCommand:
				debug_log("CTAP_clientPIN_subCommand" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->subCommand));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_clientPIN_subCommand);
				break;

			case CTAP_clientPIN_keyAgreement:
				debug_log("CTAP_clientPIN_keyAgreement" nl);
				ctap_parse_check(parse_cose_key(&map, &params->keyAgreement));
				ctap_set_present(params, CTAP_clientPIN_keyAgreement);
				break;

			case CTAP_clientPIN_pinUvAuthParam:
				debug_log("CTAP_clientPIN_pinUvAuthParam" nl);
				ctap_parse_check(parse_byte_string(
					&map,
					params->pinUvAuthParam,
					&params->pinUvAuthParam_size,
					CTAP_PIN_UV_AUTH_PARAM_MIN_SIZE,
					CTAP_PIN_UV_AUTH_PARAM_MAX_SIZE,
					&map
				));
				ctap_set_present(params, CTAP_clientPIN_pinUvAuthParam);
				break;

			case CTAP_clientPIN_newPinEnc:
				debug_log("CTAP_clientPIN_newPinEnc" nl);
				ctap_parse_check(parse_byte_string(
					&map,
					params->newPinEnc,
					&params->newPinEnc_size,
					CTAP_NEW_PIN_ENC_MIN_SIZE,
					CTAP_NEW_PIN_ENC_MAX_SIZE,
					&map
				));
				ctap_set_present(params, CTAP_clientPIN_newPinEnc);
				break;

			case CTAP_clientPIN_pinHashEnc:
				debug_log("CTAP_clientPIN_pinHashEnc" nl);
				ctap_parse_check(parse_byte_string(
					&map,
					params->pinHashEnc,
					&params->pinHashEnc_size,
					CTAP_PIN_HASH_ENC_MIN_SIZE,
					CTAP_PIN_HASH_ENC_MAX_SIZE,
					&map
				));
				ctap_set_present(params, CTAP_clientPIN_pinHashEnc);
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

		char key[2]; // not null terminated
		size_t key_length = sizeof(key);
		if (!cbor_value_is_text_string(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_copy_text_string(&map, key, &key_length, &map));

		// parse value according to the key
		if (strncmp(key, "id", key_length) == 0) {
			ctap_parse_check(parse_text_string(
				&map,
				rpId->id,
				&rpId->id_size,
				0,
				CTAP_RP_ID_MAX_SIZE,
				&map
			));
			id_parsed = true;
		} else {
			debug_log("warning: unrecognized PublicKeyCredentialRpEntity key %.*s" nl, (int) key_length, key);
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

	bool id_parsed = false;

	for (size_t i = 0; i < map_length; ++i) {

		char key[11]; // not null terminated
		size_t key_length = sizeof(key);
		if (!cbor_value_is_text_string(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_copy_text_string(&map, key, &key_length, &map));

		if (strncmp(key, "id", key_length) == 0) {
			ctap_parse_check(parse_byte_string(
				&map,
				user->id,
				&user->id_size,
				0,
				CTAP_USER_ENTITY_ID_MAX_SIZE,
				&map
			));
			id_parsed = true;
		} else if (strncmp(key, "displayName", key_length) == 0) {
			ctap_parse_check(parse_text_string(
				&map,
				user->displayName,
				&user->displayName_size,
				0,
				CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE,
				&map
			));
			user->displayName_present = true;
		} else {
			debug_log("warning: unrecognized PublicKeyCredentialUserEntity key %.*s" nl, (int) key_length, key);
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

uint8_t ctap_parse_make_credential(CborValue *it, CTAP_makeCredential *params) {

	ctap_parse_map_enter("authenticatorMakeCredential parameters");

	memset(params, 0, sizeof(CTAP_makeCredential));

	for (size_t i = 0; i < map_length; i++) {

		int key;
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		cbor_decoding_check(cbor_value_advance_fixed(&map));

		switch (key) {

			case CTAP_makeCredential_clientDataHash:
				debug_log("CTAP_makeCredential_clientDataHash" nl);
				ctap_parse_check(parse_fixed_byte_string(
					&map,
					params->clientDataHash,
					sizeof(params->clientDataHash),
					&map
				));
				ctap_set_present(params, CTAP_makeCredential_clientDataHash);
				break;

			case CTAP_makeCredential_rp:
				debug_log("CTAP_makeCredential_rp" nl);
				ctap_parse_check(parse_rp_entity(
					&map,
					&params->rpId
				));
				ctap_set_present(params, CTAP_makeCredential_rp);
				break;

			case CTAP_makeCredential_user:
				debug_log("CTAP_makeCredential_user" nl);
				ctap_parse_check(parse_user_entity(
					&map,
					&params->user
				));
				ctap_set_present(params, CTAP_makeCredential_user);
				break;

			case CTAP_makeCredential_pubKeyCredParams:
				debug_log("CTAP_makeCredential_pubKeyCredParams" nl);
				if (!cbor_value_is_array(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				params->pubKeyCredParams = map;
				cbor_decoding_check(cbor_value_advance(&map));
				ctap_set_present(params, CTAP_makeCredential_pubKeyCredParams);
				break;

			case CTAP_makeCredential_excludeList:
				debug_log("CTAP_makeCredential_excludeList" nl);
				if (!cbor_value_is_array(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				params->excludeList = map;
				cbor_decoding_check(cbor_value_advance(&map));
				ctap_set_present(params, CTAP_makeCredential_excludeList);
				break;

				// case CTAP_makeCredential_options:
				// 	debug_log("CTAP_makeCredential_options" nl);
				// 	// TODO
				// 	mc->params.options = true;
				// 	break;

			case CTAP_makeCredential_pinUvAuthParam:
				debug_log("CTAP_makeCredential_pinUvAuthParam" nl);
				ctap_parse_check(parse_byte_string(
					&map,
					params->pinUvAuthParam,
					&params->pinUvAuthParam_size,
					0,
					CTAP_PIN_UV_AUTH_PARAM_MAX_SIZE,
					&map
				));
				ctap_set_present(params, CTAP_makeCredential_pinUvAuthParam);
				break;

			case CTAP_makeCredential_pinUvAuthProtocol:
				debug_log("CTAP_makeCredential_pinUvAuthProtocol" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(ctap_cbor_value_get_uint8(&map, &params->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				ctap_set_present(params, CTAP_makeCredential_pinUvAuthProtocol);
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
