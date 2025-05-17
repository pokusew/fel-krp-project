#include "ctap.h"

/**
 * This function prepares the pinUvAuthToken for use by the platform,
 * which has invoked one of the pinUvAuthToken-issuing operations,
 * by setting particular pinUvAuthToken state variables to given use-case-specific values.
 * See also 6.5.5.7 Operations to Obtain a pinUvAuthToken.
 */
void ctap_pin_uv_auth_token_begin_using(
	ctap_state_t *const state,
	const bool user_is_present,
	const uint32_t permissions
) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	// permissions (scoped to the RP ID, if later set)
	memset(&token_state->rpId_hash, 0, sizeof(token_state->rpId_hash));
	token_state->rpId_set = false;
	token_state->permissions = permissions;
	// user flags
	token_state->user_present = user_is_present;
	token_state->user_verified = true;
	// timer
	token_state->initial_usage_time_limit = CTAP_PIN_UV_AUTH_TOKEN_INITIAL_USAGE_TIME_LIMIT_USB;
	token_state->user_present_time_limit = CTAP_PIN_UV_AUTH_TOKEN_INITIAL_USAGE_TIME_LIMIT_USB;
	token_state->max_usage_time_period = CTAP_PIN_UV_AUTH_TOKEN_MAX_USAGE_TIME_PERIOD;
	token_state->usage_timer.start = state->current_time;
	// the in_use flag
	token_state->in_use = true;
}

/**
 * This function implements the pinUvAuthTokenUsageTimerObserver()
 * (see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinuvauthprotocol-pinuvauthtokenusagetimerobserver)
 *
 * * If the pinUvAuthToken is NOT in use, this function does nothing and returns false.
 *
 * * If the pinUvAuthToken is in use, this function checks the usage_timer values
 *   (the elapsed time since the creation of the pinUvAuthToken and the elapsed time since the last use)
 *   against the various time limits (max_usage_time_period, initial_usage_time_limit, user_present_time_limit).
 *
 * * If a limit is reached that causes the pinUvAuthToken to expire, this function invokes
 *   ctap_pin_uv_auth_token_stop_using(), which invalidates the pinUvAuthToken (i.e., sets the in_use flag to false
 *   and clears all other state variables as well) and this function returns true.
 *   Note that the ctap_pin_uv_auth_token_stop_using() also invokes ctap_discard_stateful_command_state().
 *   The caller can perform any additional cleanup steps on the pinUvAuthToken
 *   expiration (which is signalized by the true return value).
 *
 *  * If only a user_present_time_limit is reached, this function invokes
 *    ctap_pin_uv_auth_token_clear_user_present_flag(), which clears the user_present flag,
 *    but the pinUvAuthToken remains valid (this function returns false).
 *
 * @param state the CTAP state
 * @retval true if the pinUvAuthToken has just expired
 * @retval false if the pinUvAuthToken was not in use, or it is still valid (it have not expired yet)
 */
bool ctap_pin_uv_auth_token_check_usage_timer(ctap_state_t *const state) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;

	if (!token_state->in_use) {
		return false;
	}

	const uint32_t current_time = state->current_time;

	// max usage time limit
	const uint32_t elapsed_since_start = current_time - token_state->usage_timer.start;
	if (elapsed_since_start > token_state->max_usage_time_period) {
		ctap_pin_uv_auth_token_stop_using(state);
		return true;
	}

	// initial usage time limit (the pinUvAuthToken MUST be used at least once
	// within this time limit in order for it to remain valid for the full max usage time limit)
	const bool used_at_least_once = token_state->usage_timer.last_use > token_state->usage_timer.start;
	if (!used_at_least_once && elapsed_since_start > token_state->initial_usage_time_limit) {
		ctap_pin_uv_auth_token_stop_using(state);
		return true;
	}

	// rolling timer:
	//   Fully functional, but disabled for now to better accommodate infrequent user interactions,
	//   which are typical for authenticatorCredentialManagement.
	//   See the related note in the spec (below the rolling timer definition):
	//     https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#puatoken-rolling-timer
	//   Alternatively, we could enable the rolling timer based on the pinUvAuthToken's permissions
	//   - i.e., only enable the rolling timer when the pinUvAuthToken is NOT used
	//           for the authenticatorCredentialManagement command.
	// if (!ctap_pin_uv_auth_token_has_permissions(state, CTAP_clientPIN_pinUvAuthToken_permission_cm)) {
	// 	const uint32_t elapsed_since_last_use = current_time - token_state->usage_timer.last_use;
	// 	if (elapsed_since_last_use > token_state->initial_usage_time_limit) {
	// 		ctap_pin_uv_auth_token_stop_using(state);
	// 		return true;
	// 	}
	// }

	// remove cached user presence if the user present time limit is reached
	if (token_state->user_present && elapsed_since_start > token_state->user_present_time_limit) {
		ctap_pin_uv_auth_token_clear_user_present_flag(state);
	}

	return false;
}

bool ctap_pin_uv_auth_token_get_user_present_flag_value(const ctap_state_t *const state) {
	const ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	return token_state->in_use ? token_state->user_present : false;
}

bool ctap_pin_uv_auth_token_get_user_verified_flag_value(const ctap_state_t *const state) {
	const ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	return token_state->in_use ? token_state->user_verified : false;
}

void ctap_pin_uv_auth_token_clear_user_present_flag(ctap_state_t *const state) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	if (token_state->in_use) {
		token_state->user_present = false;
	}
}

void ctap_pin_uv_auth_token_clear_user_verified_flag(ctap_state_t *const state) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	if (token_state->in_use) {
		token_state->user_verified = false;
	}
}

void ctap_pin_uv_auth_token_clear_permissions_except_lbw(ctap_state_t *const state) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	if (token_state->in_use) {
		token_state->permissions = token_state->permissions & CTAP_clientPIN_pinUvAuthToken_permission_lbw;
	}
}

bool ctap_pin_uv_auth_token_has_permissions(const ctap_state_t *const state, const uint32_t permissions) {
	const ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	return token_state->in_use ? (token_state->permissions & permissions) == permissions : false;
}

void ctap_pin_uv_auth_token_stop_using(ctap_state_t *const state) {
	ctap_pin_uv_auth_token_state *const token_state = &state->pin_uv_auth_token_state;
	if (!token_state->in_use) {
		return;
	}
	// ctap_pin_uv_auth_token_stop_using() is invoked
	// a) by ctap_pin_uv_auth_token_check_usage_timer()
	//    when the pinUvAuthToken has just expired
	// b) by ctap_all_pin_protocols_reset_pin_uv_auth_token()
	//    when all pinUvAuthTokens have just been regenerated (invalidated)
	// The spec, 6. Authenticator API, stateful commands:
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#stateful-commands
	//   An authenticator MUST discard the state for a stateful command
	//   if the pinUvAuthToken that authenticated the state initializing command
	//   expires since the stateful commands do not themselves always verify a pinUvAuthToken.
	debug_log(yellow("the pinUvAuthToken has just expired or been invalidated") nl);
	if (ctap_has_stateful_command_state(state)) {
		debug_log(
			red(
				"discarding the state of the stateful command %d because"
				" the pinUvAuthToken has just expired / been invalidated"
			) nl,
			state->stateful_command_state.active_cmd
		);
		ctap_discard_stateful_command_state(state);
	}
	// This sets all of the pinUvAuthToken's state variables
	// to 0 and false (which are their initial values).
	memset(token_state, 0, sizeof(ctap_pin_uv_auth_token_state));
}
