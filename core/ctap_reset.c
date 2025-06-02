#include "ctap.h"

uint8_t ctap_reset(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	// This command does not take any parameters.
	lion_unused(it);
	// This command does return any response data (only the status code).
	lion_unused(encoder);

	// 6.6. authenticatorReset (0x07)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset

	// * In order to prevent an accidental triggering of this mechanism,
	//   evidence of user interaction is required.
	// * In case of authenticators with no display,
	//   request MUST have come to the authenticator within 10 seconds of powering up of the authenticator.
	// * If the request comes after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED.
#if LIONKEY_DEVELOPMENT_OVERRIDE != 1
	const uint32_t elapsed_ms_since_power_on = state->current_time - state->init_time;
	if (elapsed_ms_since_power_on > (10 * 1000)) {
		debug_log(red("reset command received after 10 seconds of powering up") nl);
		return CTAP2_ERR_NOT_ALLOWED;
	}
#endif

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
			if (state->storage->erase(state->storage) != CTAP_STORAGE_OK) {
				error_log("storage->erase failed" nl);
				return CTAP1_ERR_OTHER;
			}
			ctap_init(state);
			return CTAP2_OK;
	}

	// This return should never be reached because the switch statement
	// covers all of the ctap_user_presence_result enum values.
	// We add it here to avoid compiler wantings.
	return CTAP2_ERR_OPERATION_DENIED;

}
