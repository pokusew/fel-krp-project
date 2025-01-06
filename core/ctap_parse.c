#include "ctap_parse.h"
#include <cbor.h>

uint8_t parse_fixed_byte_string(CborValue *map, uint8_t *dst, unsigned int len) {
	size_t sz;
	int ret;
	if (cbor_value_get_type(map) == CborByteStringType) {
		sz = len;
		ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
		check_ret(ret);
		if (sz != len) {
			printf2(TAG_ERR, "error byte string is different length (%d vs %d)" nl, len, sz);
			return CTAP1_ERR_INVALID_LENGTH;
		}
	} else {
		printf2(TAG_ERR, "error, CborByteStringType expected" nl);
		return CTAP2_ERR_INVALID_CBOR_TYPE;
	}
	return 0;
}

uint8_t ctap_parse_client_pin(const uint8_t *request, size_t length, CTAP_clientPIN *cp) {

	uint8_t ret;
	CborError err;

	int key;
	size_t map_length;
	size_t sz;

	CborParser parser;
	CborValue it;
	CborValue map;

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
		// read map key
		if (cbor_value_is_integer(&map)) {
			return CTAP2_ERR_INVALID_CBOR_TYPE;
		}
		cbor_decoding_check(cbor_value_get_int_checked(&map, &key));

		cbor_decoding_check(cbor_value_advance(&map));

		switch (key) {
			case CTAP_clientPIN_pinUvAuthProtocol:
				printf("CTAP_clientPIN_pinUvAuthProtocol" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_INVALID_CBOR_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cp->pinUvAuthProtocol));
				break;
			case CTAP_clientPIN_subCommand:
				printf("CTAP_clientPIN_subCommand" nl);
				if (!cbor_value_is_unsigned_integer(&map)) {
					return CTAP2_ERR_INVALID_CBOR_TYPE;
				}
				cbor_decoding_check(cbor_value_get_int_checked(&map, &cp->subCommand));
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
				if (cbor_value_is_byte_string())
				ret = parse_fixed_byte_string(&map, cp->pinUvAuthParam, 16);
				check_retr(ret);
				cp->pinAuthPresent = true;
				break;
			case CP_newPinEnc:
				printf1(TAG_CP, "CP_newPinEnc" nl);
				if (cbor_value_get_type(&map) == CborByteStringType) {
					ret = cbor_value_calculate_string_length(&map, &sz);
					check_ret(ret);
					if (sz > NEW_PIN_ENC_MAX_SIZE || sz < NEW_PIN_ENC_MIN_SIZE) {
						return CTAP2_ERR_PIN_POLICY_VIOLATION;
					}

					CP->newPinEncSize = sz;
					sz = NEW_PIN_ENC_MAX_SIZE;
					ret = cbor_value_copy_byte_string(&map, CP->newPinEnc, &sz, NULL);
					check_ret(ret);
				} else {
					return CTAP2_ERR_INVALID_CBOR_TYPE;
				}

				break;
			case CP_pinHashEnc:
				printf1(TAG_CP, "CP_pinHashEnc" nl);

				ret = parse_fixed_byte_string(&map, CP->pinHashEnc, 16);
				check_retr(ret);
				CP->pinHashEncPresent = 1;

				break;
			case CP_getKeyAgreement:
				printf1(TAG_CP, "CP_getKeyAgreement" nl);
				if (cbor_value_get_type(&map) != CborBooleanType) {
					printf2(TAG_ERR, "Error, expecting cbor boolean" nl);
					return CTAP2_ERR_INVALID_CBOR_TYPE;
				}
				ret = cbor_value_get_boolean(&map, &CP->getKeyAgreement);
				check_ret(ret);
				break;
			case CP_getRetries:
				printf1(TAG_CP, "CP_getRetries" nl);
				if (cbor_value_get_type(&map) != CborBooleanType) {
					printf2(TAG_ERR, "Error, expecting cbor boolean" nl);
					return CTAP2_ERR_INVALID_CBOR_TYPE;
				}
				ret = cbor_value_get_boolean(&map, &CP->getRetries);
				check_ret(ret);
				break;
			default:
				printf1(TAG_CP, "Unknown key %d" nl, key);
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);

	}


	return 0;
}
