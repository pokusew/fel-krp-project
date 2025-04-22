#include "ctap.h"

static const uint32_t ctap_get_info_options_present = 0u
	| CTAP_getInfo_option_plat
	| CTAP_getInfo_option_rk
	| CTAP_getInfo_option_clientPin
	| CTAP_getInfo_option_up
	| CTAP_getInfo_option_pinUvAuthToken
	| CTAP_getInfo_option_credMgmt
	| CTAP_getInfo_option_makeCredUvNotRqd;
static const uint32_t ctap_get_info_options_static_values = 0u
	| CTAP_getInfo_option_rk
	| CTAP_getInfo_option_up
	| CTAP_getInfo_option_pinUvAuthToken
	| CTAP_getInfo_option_credMgmt
	| CTAP_getInfo_option_makeCredUvNotRqd;

bool ctap_get_info_is_option_present(const ctap_state_t *state, const uint32_t option) {
	return (ctap_get_info_options_present & option) == option;
}

const uint8_t ctap_aaguid[CTAP_AAGUID_SIZE] = "\xa8\xa1\x47\x32\x6b\x7d\x12\x0d\xfb\x91\x73\x56\xbc\x18\x98\x03";

bool ctap_get_info_is_option_present_with(const ctap_state_t *state, const uint32_t option, const bool value) {
	if (!ctap_get_info_is_option_present(state, option)) {
		return false;
	}
	// dynamic options
	if (option == CTAP_getInfo_option_clientPin) {
		// If present, it indicates that the device is capable of accepting a PIN from the client
		// ->  if true, it indicates that PIN has been set
		// -> if false, it indicates that PIN has not been set yet
		return state->persistent.is_pin_set;
	}
	// static options
	const bool option_value = (ctap_get_info_options_static_values & option) == option;
	return option_value == value;
}

bool ctap_get_info_is_option_absent(const ctap_state_t *state, const uint32_t option) {
	return !ctap_get_info_is_option_present(state, option);
}

uint8_t ctap_get_info(ctap_state_t *state) {

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;
	CborError err;

	CborEncoder array;
	CborEncoder options;
	CborEncoder pins;

	// TODO: Review all options
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 8));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_versions));
	cbor_encoding_check(cbor_encoder_create_array(&map, &array, 1));
	cbor_encoding_check(cbor_encode_text_string(&array, "FIDO_2_1", 8));
	cbor_encoding_check(cbor_encoder_close_container(&map, &array));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_extensions));
	cbor_encoding_check(cbor_encoder_create_array(&map, &array, 2));
	cbor_encoding_check(cbor_encode_text_string(&array, "credProtect", 11));
	cbor_encoding_check(cbor_encode_text_string(&array, "hmac-secret", 11));
	cbor_encoding_check(cbor_encoder_close_container(&map, &array));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_aaguid));
	cbor_encoding_check(cbor_encode_byte_string(&map, ctap_aaguid, sizeof(ctap_aaguid)));

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
