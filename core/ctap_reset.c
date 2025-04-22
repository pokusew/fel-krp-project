#include "ctap.h"

uint8_t ctap_reset(ctap_state_t *state) {

	// 6.6. authenticatorReset (0x07)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset

	// * In order to prevent an accidental triggering of this mechanism,
	//   evidence of user interaction is required.

	// TODO:
	//  * In case of authenticators with no display,
	//   request MUST have come to the authenticator within 10 seconds of powering up of the authenticator.
	//  * If the request comes after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED

	// Response:
	// * If all conditions are met, authenticator returns CTAP2_OK.
	// * If this command is disabled for the transport used, the authenticator returns CTAP2_ERR_OPERATION_DENIED.
	// * If user presence is explicitly denied, the authenticator returns CTAP2_ERR_OPERATION_DENIED.

	ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
	switch (up_result) {
		case CTAP_UP_RESULT_CANCEL:
			// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
			return CTAP2_ERR_KEEPALIVE_CANCEL;
		case CTAP_UP_RESULT_TIMEOUT:
			// If a user action timeout occurs, the authenticator returns CTAP2_ERR_USER_ACTION_TIMEOUT.
			return CTAP2_ERR_USER_ACTION_TIMEOUT;
		case CTAP_UP_RESULT_DENY:
			// If user presence is explicitly denied, the authenticator returns CTAP2_ERR_OPERATION_DENIED.
			return CTAP2_ERR_OPERATION_DENIED;
		case CTAP_UP_RESULT_ALLOW:
			// If all conditions are met (1. evidence of user interaction collected
			// and 2. the request came within 10 seconds of powering up), authenticator returns CTAP2_OK.
			ctap_send_keepalive_if_needed(CTAP_STATUS_PROCESSING);
			ctap_init(state); // TODO: Update once we implement the state persistence.
			return CTAP2_OK;
	}

}
