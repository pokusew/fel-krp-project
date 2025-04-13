#ifndef LIONKEY_CTAP_H
#define LIONKEY_CTAP_H

#include "ctap_parse.h"
#include "compiler.h"
#include <cbor.h>
#include <hmac.h>

typedef enum LION_ATTR_PACKED ctap_command {
	CTAP_CMD_MAKE_CREDENTIAL = 0x01,
	CTAP_CMD_GET_ASSERTION = 0x02,
	CTAP_CMD_GET_NEXT_ASSERTION = 0x08,
	CTAP_CMD_GET_INFO = 0x04,
	CTAP_CMD_CLIENT_PIN = 0x06,
	CTAP_CMD_RESET = 0x07,
	CTAP_CMD_BIO_ENROLLMENT = 0x09,
	CTAP_CMD_CREDENTIAL_MANAGEMENT = 0x0A,
	CTAP_CMD_SELECTION = 0x0B,
	CTAP_CMD_LARGE_BLOBS = 0x0C,
	CTAP_CMD_CONFIG = 0x0D,
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#commands
	CTAP_VENDOR_FIRST = 0x40,
	CTAP_VENDOR_LAST = 0xBF,
} ctap_command_t;
static_assert(sizeof(ctap_command_t) == sizeof(uint8_t), "invalid sizeof(ctaphid_command_t)");

#define KEY_SPACE_BYTES     128
#define PIN_HASH_SIZE       16

#define EMPTY_MARKER        0xFFFFFFFF
#define INITIALIZED_MARKER  0xA5A5A5A5
#define INVALID_MARKER      0xDDDDDDDD

#define PIN_TOTAL_ATTEMPTS     8
#define PIN_PER_BOOT_ATTEMPTS  3
static_assert(
	PIN_PER_BOOT_ATTEMPTS < PIN_TOTAL_ATTEMPTS,
	"PIN_TOTAL_ATTEMPTS must be greater than or equal to PIN_PER_BOOT_ATTEMPTS"
);

typedef struct ctap_persistent_state {

	// PIN information
	bool is_pin_set;
	// from the spec we can derive that 4 <= pin_code_point_length <= 63
	uint8_t pin_code_point_length;
	uint8_t pin_hash[PIN_HASH_SIZE];
	uint8_t pin_total_remaining_attempts;

	// number of stored client-side discoverable credentials
	// aka resident credentials aka resident keys (RK)
	uint16_t num_rk_stored;

	// master keys data
	uint8_t master_keys[KEY_SPACE_BYTES];

	uint8_t _alignment1;

	// this field must be WORD (32 bytes) aligned
	uint32_t is_invalid;
	// this field must be WORD (32 bytes) aligned
	// note: in order for the data loss prevention logic to work, is_initialized must be the last field
	uint32_t is_initialized;

} ctap_persistent_state_t;

#define CTAP_RESPONSE_BUFFER_SIZE   4096

typedef struct ctap_response {
	CborEncoder encoder;
	size_t length;
	uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
} ctap_response_t;

#define PIN_TOKEN_SIZE 32

/// 6.5. authenticatorClientPIN (0x06)
/// 6.5.4. PIN/UV Auth Protocol Abstract Definition
///
/// PIN/UV Auth Protocol exists so that plaintext PINs are not sent to the authenticator.
/// Instead, a PIN/UV auth protocol (aka pinUvAuthProtocol) ensures that PINs
/// are encrypted when sent to an authenticator and are exchanged for a pinUvAuthToken
/// that serves to authenticate subsequent commands.
/// Additionally, authenticators supporting built-in user verification methods
/// can provide a pinUvAuthToken upon user verification.
///
/// Note:
///   PIN/UV Auth Protocol One was essentially defined in CTAP2.0.
///   The difference between the original definition and the definition in CTAP2.1
///   is that originally the pinToken (pinUvAuthToken in CTAP2.1 terms) length was unlimited.
///   CTAP2.1 specifies lengths for pinUvAuthTokens
///   in both PIN/UV Auth Protocol 1 and in PIN/UV Auth Protocol 2.
typedef struct ctap_pin_protocol {

	uint8_t pin_uv_auth_token[PIN_TOKEN_SIZE];
	uint8_t key_agreement_public_key[64];
	uint8_t key_agreement_private_key[32];
	size_t shared_secret_length;
	size_t encryption_extra_length;

	/// This process is run by the authenticator at power-on.
	int (*initialize)(
		struct ctap_pin_protocol *protocol
	);

	/// Generates a fresh public key.
	int (*regenerate)(
		struct ctap_pin_protocol *protocol
	);

	/// Generates a fresh pinUvAuthToken.
	int (*reset_pin_uv_auth_token)(
		struct ctap_pin_protocol *protocol
	);

	int (*get_public_key)(
		struct ctap_pin_protocol *protocol,
		CborEncoder *encoder
	);

	/// Processes the output of encapsulate from the peer and produces a shared secret,
	/// known to both platform and authenticator.
	int (*decapsulate)(
		const struct ctap_pin_protocol *protocol,
		const COSE_Key *peer_cose_key,
		uint8_t *shared_secret
	);

	/**
	 * Encrypt a plaintext using a shared secret as a key and outputs a ciphertext to the given ciphertext buffer.
	 *
	 * The plaintext remains unchanged.
	 *
	 * @param shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                      (32 bytes for v1, 64 bytes for v2)
	 * @param plaintext the plaintext
	 * @param plaintext_length the plaintext length in bytes
	 * @param ciphertext the pointer to an array of size at least (plaintext_length + encryption_extra_length) bytes
	 *                   where the ciphertext will be written
	 * @return 0 on success, 1 on error
	 */
	int (*encrypt)(
		const uint8_t *shared_secret,
		const uint8_t *plaintext, const size_t plaintext_length,
		uint8_t *ciphertext
	);

	/**
	 * Decrypts a ciphertext using a shared secret as a key and outputs a plaintext to the given plaintext buffer.
	 *
	 * The ciphertext remains unchanged.
	 *
	 * @param shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                      (32 bytes for v1, 64 bytes for v2)
	 * @param ciphertext the ciphertext
	 * @param ciphertext_length the ciphertext length in bytes
	 * @param plaintext the pointer to an array of size at least (ciphertext_length - encryption_extra_length) bytes
	 *                  where
	 * @return 0 on success, 1 on error
	 */
	int (*decrypt)(
		const uint8_t *shared_secret,
		const uint8_t *ciphertext, const size_t ciphertext_length,
		uint8_t *plaintext
	);

	/// Verifies that the signature is a valid MAC for the given message.
	/// If the key parameter value is the current pinUvAuthToken,
	/// it also checks whether the pinUvAuthToken is in use or not.
	void (*verify_init)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		// Note that key is always either a shared_secret (v1 32 bytes or v2 64 bytes)
		// or pin_uv_auth_token (32 bytes).
		const uint8_t *key, const size_t key_length
	);
	void (*verify_update)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		const uint8_t *message_data, const size_t message_data_length
	);
	int (*verify_final)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		const uint8_t *signature, const size_t signature_length
	);
} ctap_pin_protocol_t;

#define CTAP_PIN_UV_AUTH_TOKEN_STATE_INITIAL_USAGE_TIME_LIMIT_USB (30 * 1000)

typedef struct ctap_timer {
	bool running;
	uint32_t start;
} ctap_timer;

/**
 * 6.5.2.1. pinUvAuthToken State
 * https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-globalState-puat
 */
typedef struct ctap_pin_uv_auth_token_state {

	/**
	 * A permissions RP ID, initially null.
	 */
	CTAP_rpId rpId;
	bool rpId_set;

	/**
	 * A permissions set whose possible values are those of pinUvAuthToken permissions.
	 * It is initially empty.
	 */
	uint32_t permissions;

	/**
	 * A usage timer, initially not running.
	 * Note: Once running, the timer is observed by pin_uv_auth_token_usage_timer_observer().
	 */
	ctap_timer usage_timer;

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
	 */
	bool user_present;

} ctap_pin_uv_auth_token_state;

typedef struct ctap_state {

	ctap_persistent_state_t persistent;

	ctap_response_t response;

	ctap_pin_protocol_t pin_protocol[2];
	uint8_t pin_boot_remaining_attempts;
	ctap_pin_uv_auth_token_state pin_uv_auth_token_state;

} ctap_state_t;

typedef enum ctap_user_presence_result {
	CTAP_UP_RESULT_CANCEL,
	CTAP_UP_RESULT_TIMEOUT,
	CTAP_UP_RESULT_DENY,
	CTAP_UP_RESULT_ALLOW,
} ctap_user_presence_result_t ;

ctap_user_presence_result_t ctap_wait_for_user_presence(void);

uint8_t ctap_request(
	ctap_state_t *state,
	uint8_t cmd,
	size_t params_size,
	const uint8_t *params
);

void ctap_init(ctap_state_t *state);

void ctap_rng_reset(uint32_t seed);

int ctap_generate_rng(uint8_t *buffer, size_t length);

uint8_t ctap_get_info(ctap_state_t *state);

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length);

void ctap_pin_protocol_v1_init(ctap_pin_protocol_t *protocol);

void ctap_pin_uv_auth_token_begin_using(ctap_pin_uv_auth_token_state *token_state, bool user_is_present);

void ctap_pin_uv_auth_token_usage_timer_observer(ctap_pin_uv_auth_token_state *token_state);

bool ctap_pin_uv_auth_token_get_user_present_flag_value(ctap_pin_uv_auth_token_state *token_state);

bool ctap_pin_uv_auth_token_get_user_verified_flag_value(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_clear_user_present_flag(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_clear_permissions_except_lbw(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_stop_using(ctap_pin_uv_auth_token_state *token_state);

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length);

#endif // LIONKEY_CTAP_H
