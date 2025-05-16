#include "ctap.h"

uint8_t ctap_encode_ctap_string_as_byte_string(
	CborEncoder *const encoder,
	const ctap_string_t *const str
) {
	CborError err;
	cbor_encoding_check(cbor_encode_byte_string(encoder, str->data, str->size));
	return CTAP2_OK;
}

uint8_t ctap_encode_ctap_string_as_text_string(
	CborEncoder *const encoder,
	const ctap_string_t *const str
) {
	CborError err;
	cbor_encoding_check(cbor_encode_text_string(encoder, (const char *) str->data, str->size));
	return CTAP2_OK;
}

uint8_t ctap_encode_public_key(
	CborEncoder *const encoder,
	const uint8_t *const public_key
) {

	const uint8_t *const x = public_key;
	const uint8_t *const y = public_key + 32;

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

uint8_t ctap_encode_pub_key_cred_desc(
	CborEncoder *const encoder,
	const size_t cred_id_size,
	const uint8_t *const cred_id_data
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

uint8_t ctap_encode_pub_key_cred_user_entity(
	CborEncoder *const encoder,
	const CTAP_userEntity *const user,
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
	ctap_check(ctap_encode_ctap_string_as_byte_string(&map, &user->id));

	if (include_user_identifiable_info && ctap_param_is_present(user, CTAP_userEntity_name)) {
		cbor_encoding_check(cbor_encode_text_string(&map, "name", 4));
		ctap_check(ctap_encode_ctap_string_as_text_string(&map, &user->name));
	}

	if (include_user_identifiable_info && ctap_param_is_present(user, CTAP_userEntity_displayName)) {
		cbor_encoding_check(cbor_encode_text_string(&map, "displayName", 11));
		ctap_check(ctap_encode_ctap_string_as_text_string(&map, &user->displayName));
	}

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

uint8_t ctap_encode_rp_entity(
	CborEncoder *const encoder,
	const CTAP_rpId *const rp_id
) {

	uint8_t ret;
	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));

	cbor_encoding_check(cbor_encode_text_string(&map, "id", 2));
	ctap_check(ctap_encode_ctap_string_as_text_string(&map, &rp_id->id));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}
