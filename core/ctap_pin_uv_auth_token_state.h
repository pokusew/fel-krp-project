#ifndef LIONKEY_CTAP_PIN_UV_AUTH_TOKEN_STATE_H
#define LIONKEY_CTAP_PIN_UV_AUTH_TOKEN_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "ctap_common.h"

#define CTAP_PIN_UV_AUTH_TOKEN_INITIAL_USAGE_TIME_LIMIT_USB (30 * 1000) // 30 seconds (in ms)
#define CTAP_PIN_UV_AUTH_TOKEN_MAX_USAGE_TIME_PERIOD (10 * 60 * 1000) // 10 minutes (in ms)

/**
 * 6.5.2.1. pinUvAuthToken State
 * https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-globalState-puat
 */
typedef struct ctap_pin_uv_auth_token_state {

	/**
	 * A permissions RP ID, initially null.
	 */
	bool rpId_set;
	uint8_t rpId_hash[CTAP_SHA256_HASH_SIZE];

	/**
	 * A permissions set (bit flags) whose possible values are those of pinUvAuthToken permissions.
	 * It is initially empty (0).
	 * See the CTAP_clientPIN_pinUvAuthToken_permission_* definitions.
	 */
	uint32_t permissions;

	/**
	 * The "usage timer" is running iff in_use == true (the pinUvAuthToken is in use).
	 * Therefore, there is no need to explicitly store the timer's state (running vs. not running).
	 * We implement a rolling timer as described in the spec
	 * (see the excerpt in the comment at initial_usage_time_limit below).
	 */
	struct {
		uint32_t start;
		uint32_t last_use;
	} usage_timer;

	/**
	 * An in use flag, initially set to false, meaning that the pinUvAuthToken is not in use
	 * When the in use flag is set to true, the pinUvAuthToken is said to be in use.
	 */
	bool in_use;

	/**
	 * A initial usage time limit, initially not set. begin_using_pin_uv_auth_token() sets
	 * this value according to the transport the platform is using to communicate with it.
	 * The platform MUST invoke an authenticator operation using the pinUvAuthToken within
	 * this time limit for the pinUvAuthToken to remain valid for the full max usage time period.
	 * The default maximum per-transport initial usage time limit values are:
	 * * usb: 30 seconds
	 * * nfc: 19.8 seconds (16 bit counter with 3311hz clock: max time before overflow)
	 * * ble: 30 seconds
	 * * internal: 30 seconds
	 *
	 * Authenticators MAY use other values that are less than the default maximum values.
	 *
	 * Authenticators MAY implement a rolling timer, initialized to the per-transport initial
	 * usage time limit, where the pinUvAuthToken and its state variables remain valid
	 * as long as the platform again uses the pinUvAuthToken in an operation
	 * before the rolling timer expires. If so, the rolling timer is again initialized
	 * to the initial usage time limit. This continues until the max usage time period expires.
	 * See pin_uv_auth_token_usage_timer_observer().
	 *
	 * Note: Authenticators should utilize the rolling timer approach judiciously,
	 * e.g., because some features, such as authenticatorBioEnrollment and authenticatorCredentialManagement,
	 * may need to accommodate infrequent user interactions. Thus the rolling timer approach
	 * may be most applicable to authenticatorMakeCredential and authenticatorGetAssertion operations.
	 */
	uint32_t initial_usage_time_limit;

	/**
	 * A user present time limit defining the length of time the user is considered "present",
	 * as represented by the userPresent flag, after user presence is collected.
	 * The user present time limit defaults to the same default maximum per-transport values
	 * as the initial usage time limit, although authenticators MAY use other values
	 * that are less than the default maximum values, including zero.
	 * Note: The user present time limit value of zero accommodates the case
	 * where an authenticator does not wish to support maintaining "user present" state
	 * (i.e., "cached user presence").
	 */
	uint32_t user_present_time_limit;

	/**
	 * A max usage time period value, which SHOULD default to
	 * a maximum of 10 minutes (600 seconds), though authenticators
	 * MAY use other values less than the latter default,
	 * possibly depending upon the use case, e.g., which transport is in use.
	 */
	uint32_t max_usage_time_period;

	/**
	 * A userVerified flag, initially false
	 */
	bool user_verified;

	/**
	 * A userPresent flag, initially false.
	 *
	 * Note that the userPresent flag can be set to true by the
	 * CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingUvWithPermissions subcommand
	 * if the employed built-in user verification method supplies evidence of user interaction
	 * (see 6.5.5.7.3., Step 12. ... beginUsingPinUvAuthToken(userIsPresent: true)).
	 * LionKey currently does not support any built-in user verification method (thus it does not implement
	 * the CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingUvWithPermissions subcommand).
	 * Therefore the userPresent flag is always false and we could remove all the related logic from our code.
	 * For now, we decided to keep the already-implemented logic in place in we case we added support
	 * for some built-in user verification method in the future.
	 */
	bool user_present;

} ctap_pin_uv_auth_token_state;

#endif // LIONKEY_CTAP_PIN_UV_AUTH_TOKEN_STATE_H
