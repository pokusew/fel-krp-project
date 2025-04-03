#include "ctap_parse.h"
#include <cbor.h>

uint8_t parse_fixed_byte_string(const CborValue *value, uint8_t *buffer, size_t expected_length, CborValue *next) {

	CborError err;

	if (!cbor_value_is_byte_string(value)) {
		printf("parse_fixed_byte_string: not a byte string" nl);
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
		printf("parse_fixed_byte_string: invalid length: actual %zu < expected %zu" nl, length, expected_length);
		return CTAP1_ERR_INVALID_LENGTH; // TODO: Use CTAP2_ERR_CBOR_UNEXPECTED_TYPE?
	}

	return CTAP2_OK;

}

uint8_t parse_byte_string(
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
		printf("parse_fixed_byte_string: not a byte string" nl);
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

uint8_t parse_cose_key(CborValue *it, COSE_Key *cose) {

	uint8_t ret;
	CborError err;

	CborValue map;
	size_t map_length;
	int key;

	bool pubkey_x_parsed = false;
	bool pubkey_y_parsed = false;
	cose->kty = 0;
	cose->crv = 0;

	if (!cbor_value_is_map(it)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	cbor_decoding_check(cbor_value_enter_container(it, &map));

	cbor_decoding_check(cbor_value_get_map_length(it, &map_length));

	printf("COSE_Key map has %zu elements" nl, map_length);

	for (size_t i = 0; i < map_length; i++) {
		// read the current key
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		// advance to the corresponding value
		cbor_decoding_check(cbor_value_advance_fixed(&map));
		// parse the value according to the key
		switch (key) {
			case COSE_KEY_LABEL_KTY:
				printf("COSE_KEY_LABEL_KTY" nl);
				if (!cbor_value_is_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose->kty));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;
			case COSE_KEY_LABEL_ALG:
				printf("COSE_KEY_LABEL_ALG" nl);
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
				printf("COSE_KEY_LABEL_CRV" nl);
				if (!cbor_value_is_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cose->crv));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;
			case COSE_KEY_LABEL_X:
				printf("COSE_KEY_LABEL_X" nl);
				if ((ret = parse_fixed_byte_string(&map, cose->pubkey.x, 32, &map)) != CTAP2_OK) {
					return ret;
				}
				pubkey_x_parsed = true;
				break;
			case COSE_KEY_LABEL_Y:
				printf("COSE_KEY_LABEL_Y" nl);
				if ((ret = parse_fixed_byte_string(&map, cose->pubkey.y, 32, &map)) != CTAP2_OK) {
					return ret;
				}
				pubkey_y_parsed = true;
				break;
			default:
				printf("warning: unrecognized cose key option %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	cbor_value_leave_container(it, &map);

	// validate
	if (pubkey_x_parsed == 0 || pubkey_y_parsed == 0 || cose->kty == 0 || cose->crv == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return CTAP2_OK;

}

uint8_t ctap_parse_client_pin(const uint8_t *request, size_t length, CTAP_clientPIN *cp) {

	CborParser parser;
	CborValue it;

	uint8_t ret;
	CborError err;

	CborValue map;
	size_t map_length;
	int key;

	memset(cp, 0, sizeof(CTAP_clientPIN));

	cbor_decoding_check(
		cbor_parser_init(
			request,
			length,
			CborValidateCanonicalFormat,
			&parser,
			&it
		)
	);

	if (!cbor_value_is_map(&it)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	cbor_decoding_check(cbor_value_enter_container(&it, &map));

	cbor_decoding_check(cbor_value_get_map_length(&it, &map_length));

	printf("CTAP_clientPIN map has %zu elements" nl, map_length);

	for (size_t i = 0; i < map_length; i++) {
		// read the current key
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		// advance to the corresponding value
		cbor_decoding_check(cbor_value_advance_fixed(&map));
		// parse the value according to the key
		switch (key) {
			case CTAP_clientPIN_pinUvAuthProtocol:
				printf("CTAP_clientPIN_pinUvAuthProtocol" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cp->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;
			case CTAP_clientPIN_subCommand:
				printf("CTAP_clientPIN_subCommand" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cp->subCommand));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;
			case CTAP_clientPIN_keyAgreement:
				printf("CTAP_clientPIN_keyAgreement" nl);
				if ((ret = parse_cose_key(&map, &cp->keyAgreement)) != CTAP2_OK) {
					return ret;
				}
				cp->keyAgreementPresent = true;
				break;
			case CTAP_clientPIN_pinUvAuthParam:
				printf("CTAP_clientPIN_pinUvAuthParam" nl);
				if ((
						ret = parse_byte_string(
							&map,
							cp->pinUvAuthParam,
							&cp->pinUvAuthParamSize,
							PIN_UV_AUTH_PARAM_MIN_SIZE,
							PIN_UV_AUTH_PARAM_MAX_SIZE,
							&map
						)) != CTAP2_OK) {
					return ret;
				}
				break;
			case CTAP_clientPIN_newPinEnc:
				printf("CTAP_clientPIN_newPinEnc" nl);
				if ((
						ret = parse_byte_string(
							&map,
							cp->newPinEnc,
							&cp->newPinEncSize,
							NEW_PIN_ENC_MIN_SIZE,
							NEW_PIN_ENC_MAX_SIZE,
							&map
						)) != CTAP2_OK) {
					return ret;
				}
				break;
			case CTAP_clientPIN_pinHashEnc:
				printf("CTAP_clientPIN_pinHashEnc" nl);
				if ((
						ret = parse_byte_string(
							&map,
							cp->pinHashEnc,
							&cp->pinHashEncSize,
							PIN_HASH_ENC_MIN_SIZE,
							PIN_HASH_ENC_MAX_SIZE,
							&map
						)) != CTAP2_OK) {
					return ret;
				}
				break;
			default:
				printf("ctap_parse_client_pin: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	return CTAP2_OK;

}

uint8_t ctap_parse_make_credential(const uint8_t *request, size_t length, CTAP_makeCredential *mc) {

	CborParser parser;
	CborValue it;

	uint8_t ret;
	CborError err;

	CborValue map;
	size_t map_length;
	int key;

	memset(mc, 0, sizeof(CTAP_makeCredential));

	cbor_decoding_check(
		cbor_parser_init(
			request,
			length,
			CborValidateCanonicalFormat,
			&parser,
			&it
		)
	);

	if (!cbor_value_is_map(&it)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	cbor_decoding_check(cbor_value_enter_container(&it, &map));

	cbor_decoding_check(cbor_value_get_map_length(&it, &map_length));

	printf("CTAP_makeCredential map has %u elements" nl, map_length);

	for (size_t i = 0; i < map_length; i++) {
		// read the current key
		if (!cbor_value_is_integer(&map)) {
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));
		// advance to the corresponding value
		cbor_decoding_check(cbor_value_advance_fixed(&map));
		// parse the value according to the key
		switch (key) {
			case CTAP_makeCredential_pinUvAuthProtocol:
				printf("CTAP_makeCredential_pinUvAuthProtocol" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &mc->pinUvAuthProtocol));
				cbor_decoding_check(cbor_value_advance_fixed(&map));
				break;
			case CTAP_makeCredential_pinUvAuthParam:
				printf("CTAP_makeCredential_pinUvAuthParam" nl);
				if ((
						ret = parse_byte_string(
							&map,
							mc->pinUvAuthParam,
							&mc->pinUvAuthParamSize,
							0,
							PIN_UV_AUTH_PARAM_MAX_SIZE,
							&map
						)) != CTAP2_OK) {
					return ret;
				}
				mc->pinUvAuthParamPresent = true;
				break;
			default:
				printf("ctap_parse_make_credential: unknown key %d" nl, key);
				cbor_decoding_check(cbor_value_advance(&map));
		}

	}

	return CTAP2_OK;

}
