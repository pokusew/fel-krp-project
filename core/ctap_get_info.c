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

static const COSEAlgorithmIdentifier ctap_supported_pub_key_cred_alg[] = {
	COSE_ALG_ES256
};
static const size_t ctap_supported_pub_key_cred_alg_count =
	sizeof(ctap_supported_pub_key_cred_alg) / sizeof(COSEAlgorithmIdentifier);

bool ctap_is_supported_pub_key_cred_alg(const CTAP_credParams *cred_params) {
	if (cred_params->type != CTAP_pubKeyCredType_public_key) {
		return false;
	}
	for (size_t i = 0; i < ctap_supported_pub_key_cred_alg_count; ++i) {
		if (ctap_supported_pub_key_cred_alg[i] == cred_params->alg) {
			return true;
		}
	}
	return false;
}

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

	// see 6.4. authenticatorGetInfo (0x04)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo

	// start response map
	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 10));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_versions));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 1));
		cbor_encoding_check(cbor_encode_text_string(&array, "FIDO_2_1", 8));
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_extensions));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, 2));
		cbor_encoding_check(cbor_encode_text_string(&array, "credProtect", 11));
		cbor_encoding_check(cbor_encode_text_string(&array, "hmac-secret", 11));
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_aaguid));
	cbor_encoding_check(cbor_encode_byte_string(&map, ctap_aaguid, sizeof(ctap_aaguid)));

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_options));
	{
		CborEncoder options;
		cbor_encoding_check(cbor_encoder_create_map(&map, &options, 7));

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

		cbor_encoding_check(cbor_encoder_close_container(&map, &options));
	}

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxMsgSize));
	cbor_encoding_check(cbor_encode_uint(&map, 1200)); // TODO

	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_pinUvAuthProtocols));
	{
		CborEncoder array;
		const size_t num_protocol_versions = sizeof(state->pin_protocols) / sizeof(ctap_pin_protocol_t);
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, num_protocol_versions));
		// List of supported PIN/UV auth protocols
		// in order of decreasing authenticator preference.
		// MUST NOT contain duplicate values nor be empty if present.
		for (size_t protocol_version = num_protocol_versions; protocol_version >= 1; --protocol_version) {
			cbor_encoding_check(cbor_encode_uint(&array, protocol_version));
		}
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// maxCredentialCountInList (0x07) specifies the maximum number of credentials supported
	// in a PublicKeyCredentialDescriptor list (authenticatorMakeCredential's excludeList
	// and authenticatorGetAssertion's allowList) at a time by the authenticator.
	// MUST be greater than zero if present.
	// Observed behavior:
	//   When maxCredentialCountInList is not present, Google Chrome defaults to 1.
	//   Our implementation supports an unlimited (*) number of credentials in excludeList and allowList.
	//   (*) = the number is limited by the maximum CTAP CBOR size. In case of the CTAPHID transport
	//   (when CTAPHID_PACKET_SIZE == 64), the maximum CTAP CBOR size is 7608 (= CTAPHID_MAX_PAYLOAD_LENGTH - 1)
	//   (the -1 for the one byte for the CTAP command code).
	//   Therefore, we set a sufficiently high number (which will effectively work as "unlimited")
	//   as the maxCredentialCountInList value.
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialCountInList));
	cbor_encoding_check(cbor_encode_uint(&map, 128));

	// Maximum Credential ID Length supported by the authenticator. MUST be greater than zero if present.
	// See Credential ID definition in WebAuthn spec at https://w3c.github.io/webauthn/#credential-id
	//   Note that the WebAuthn spec implies that every Credential ID
	//   is at least 16 bytes long and at most 1023 bytes long.
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_maxCredentialIdLength));
	cbor_encoding_check(cbor_encode_uint(&map, 128)); // TODO: update once we design our Credential ID format

	// The algorithms field is optional, but it is better to include it,
	// so that the clients can use this information to avoid sending
	// such an authenticatorMakeCredential command that would otherwise
	// result in a CTAP2_ERR_UNSUPPORTED_ALGORITHM error
	// (see ctap_parse_make_credential_pub_key_cred_params()).
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_algorithms));
	{
		CborEncoder array;
		cbor_encoding_check(cbor_encoder_create_array(&map, &array, ctap_supported_pub_key_cred_alg_count));
		for (size_t i = 0; i < ctap_supported_pub_key_cred_alg_count; ++i) {
			const COSEAlgorithmIdentifier alg = ctap_supported_pub_key_cred_alg[i];
			CborEncoder pub_key_cred_param;
			cbor_encoding_check(cbor_encoder_create_map(&array, &pub_key_cred_param, 2));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "alg", 3));
			cbor_encoding_check(cbor_encode_int(&pub_key_cred_param, alg));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "type", 4));
			cbor_encoding_check(cbor_encode_text_string(&pub_key_cred_param, "public-key", 10));
			cbor_encoding_check(cbor_encoder_close_container(&array, &pub_key_cred_param));
		}
		cbor_encoding_check(cbor_encoder_close_container(&map, &array));
	}

	// This specifies the current minimum PIN length, in Unicode code points,
	// the authenticator enforces for ClientPIN.
	// This is applicable for ClientPIN only:
	//   the minPINLength member MUST be absent if the clientPin option ID is absent;
	//   it MUST be present if the authenticator supports authenticatorClientPIN (LionKey's case).
	cbor_encoding_check(cbor_encode_uint(&map, CTAP_authenticatorGetInfo_res_minPINLength));
	cbor_encoding_check(cbor_encode_uint(&map, state->persistent.pin_min_code_point_length));

	// close response map
	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}
