#include "ctap.h"

uint8_t ctap_get_info(ctap_state_t *state) {

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;
	CborError err;

	CborEncoder array;
	CborEncoder options;
	CborEncoder pins;

	// Solo v1 aaguid
	const uint8_t aaguid[16] = "\x00\x76\x63\x1b\xd4\xa0\x42\x7f\x57\x73\x0e\xc7\x1c\x9e\x02\x79";

	// TODO: review all options
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 8));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_versions));
	cbor_encoding_check(cbor_encoder_create_array(&map, &array, 2));
	cbor_encoding_check(cbor_encode_text_stringz(&array, "FIDO_2_0"));
	cbor_encoding_check(cbor_encode_text_stringz(&array, "FIDO_2_1_PRE"));
	cbor_encoding_check(cbor_encoder_close_container(&map, &array));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_extensions));
	cbor_encoding_check(cbor_encoder_create_array(&map, &array, 2));
	cbor_encoding_check(cbor_encode_text_stringz(&array, "credProtect"));
	cbor_encoding_check(cbor_encode_text_stringz(&array, "hmac-secret"));
	cbor_encoding_check(cbor_encoder_close_container(&map, &array));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_aaguid));
	cbor_encoding_check(cbor_encode_byte_string(&map, aaguid, 16));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_options));
	cbor_encoding_check(cbor_encoder_create_map(&map, &options, 7));
	{
		// this authenticator can create discoverable credentials (not default, must be specified)
		cbor_encoding_check(cbor_encode_text_string(&options, "rk", 2));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// capable of testing user presence (this is the default, so we could omit it)
		cbor_encoding_check(cbor_encode_text_string(&options, "up", 2));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// not attached to platform (this is the default, so we could omit it)
		cbor_encoding_check(cbor_encode_text_string(&options, "plat", 4));
		cbor_encoding_check(cbor_encode_boolean(&options, false));

		// present and set to true -> the authenticatorCredentialManagement command is supported
		cbor_encoding_check(cbor_encode_text_string(&options, "credMgmt", 8));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		// If present, it indicates that the device is capable of accepting a PIN from the client
		// ->  if true, it indicates that PIN has been set
		// -> if false, it indicates that PIN has not been set yet
		cbor_encoding_check(cbor_encode_text_string(&options, "clientPin", 9));
		cbor_encoding_check(cbor_encode_boolean(&options, state->persistent.is_pin_set));

		cbor_encoding_check(cbor_encode_text_string(&options, "pinUvAuthToken", 14));
		cbor_encoding_check(cbor_encode_boolean(&options, true));

		cbor_encoding_check(cbor_encode_text_string(&options, "makeCredUvNotRqd", 16));
		cbor_encoding_check(cbor_encode_boolean(&options, true));
	}
	cbor_encoding_check(cbor_encoder_close_container(&map, &options));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxMsgSize));
	cbor_encoding_check(cbor_encode_int(&map, 1200)); // TODO

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_pinUvAuthProtocols));
	cbor_encoding_check(cbor_encoder_create_array(&map, &pins, 1));
	cbor_encoding_check(cbor_encode_int(&pins, 1));
	// TODO: add v2 once supported
	cbor_encoding_check(cbor_encoder_close_container(&map, &pins));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialCountInList));
	cbor_encoding_check(cbor_encode_uint(&map, 20)); // TODO

	// see Credential ID definition in WebAuthn spec at https://w3c.github.io/webauthn/#credential-id
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialIdLength));
	cbor_encoding_check(cbor_encode_uint(&map, 128)); // TODO: update once we design our Credential ID format

	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;
}
