#include "ctap.h"

uint8_t ctap_selection(ctap_state_t *const state, CborValue *const it, CborEncoder *const encoder) {

	// This command does not use or modify the CTAP state.
	lion_unused(state);
	// This command does not take any parameters.
	lion_unused(it);
	// This command does return any response data (only the status code).
	lion_unused(encoder);

	// 6.9. authenticatorSelection (0x0B)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorSelection

	// When the authenticatorSelection command is received, the authenticator will ask for user presence:
	ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
	switch (up_result) {
		case CTAP_UP_RESULT_CANCEL:
			// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
			return CTAP2_ERR_KEEPALIVE_CANCEL;
		case CTAP_UP_RESULT_TIMEOUT:
			// If a user action timeout occurs,
			// the authenticator will return CTAP2_ERR_USER_ACTION_TIMEOUT.
			// The platform MAY repeat the command for this authenticator.
			return CTAP2_ERR_USER_ACTION_TIMEOUT;
		case CTAP_UP_RESULT_DENY:
			// If User Presence is explicitly denied by the user,
			// the authenticator will return CTAP2_ERR_OPERATION_DENIED.
			// The platform SHOULD NOT repeat the command for this authenticator.
			return CTAP2_ERR_OPERATION_DENIED;
		case CTAP_UP_RESULT_ALLOW:
			// If User Presence is received, the authenticator will return CTAP2_OK.
			return CTAP2_OK;
	}

	// This return should never be reached because the switch statement
	// covers all of the ctap_user_presence_result enum values.
	// We add it here to avoid compiler wantings.
	return CTAP2_ERR_OPERATION_DENIED;

}
