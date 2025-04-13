#include "ctap.h"

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CborParser parser;
	CborValue it;
	ctap_parse_check(ctap_init_cbor_parser(request, length, &parser, &it));

	CTAP_makeCredential mc;
	ctap_parse_check(ctap_parse_make_credential(&it, &mc));

	// 6.1.2. authenticatorMakeCredential Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg

	// see also WebAuthn 6.3.2. The authenticatorMakeCredential Operation
	// https://w3c.github.io/webauthn/#sctn-op-make-cred

	// Google Chrome uses this request to figure out PIN state
	// a6015820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85502a1626964662e64756d6d7903a26269644101646e616d656564756d6d790481a263616c672664747970656a7075626c69632d6b657908400901
	// {
	//     1: h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
	//     2: {"id": ".dummy"},
	//     3: {"id": h'01', "name": "dummy"},
	//     4: [{"alg": -7, "type": "public-key"}],
	//     8: h'',
	//     9: 1,
	// }

	// 1. If authenticator supports either pinUvAuthToken or clientPin features
	//    and the platform sends a zero length pinUvAuthParam:
	if (ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthParam) && mc.pinUvAuthParam_size == 0) {
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
	if (ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthParam)) {
		// 2. If the pinUvAuthProtocol parameter is absent,
		//    return CTAP2_ERR_MISSING_PARAMETER error.
		if (!ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthProtocol)) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		// 1. If the pinUvAuthProtocol parameter's value is not supported,
		//    return CTAP1_ERR_INVALID_PARAMETER error.
		if (mc.pinUvAuthProtocol != 1 && mc.pinUvAuthProtocol != 2) {
			return CTAP1_ERR_INVALID_PARAMETER;
		}
	}

	// 3. Validate pubKeyCredParams and choose the first supported algorithm.
	ctap_parse_check(ctap_parse_make_credential_pub_key_cred_params(&mc));

	return CTAP1_ERR_OTHER;

}
