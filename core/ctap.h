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
#define CTAP_PIN_HASH_SIZE  16

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
	uint8_t pin_min_code_point_length;
	bool is_pin_set;
	// from the spec we can derive that 4 <= pin_code_point_length <= 63
	uint8_t pin_code_point_length;
	uint8_t pin_hash[CTAP_PIN_HASH_SIZE];
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
	const size_t data_max_size;
	uint8_t *const data;
} ctap_response_t;

#define CTAP_PIN_UV_AUTH_TOKEN_SIZE 32

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
	 */
	bool user_present;

} ctap_pin_uv_auth_token_state;

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

	uint8_t pin_uv_auth_token[CTAP_PIN_UV_AUTH_TOKEN_SIZE];
	uint8_t key_agreement_public_key[64];
	uint8_t key_agreement_private_key[32];
	size_t shared_secret_length;
	size_t encryption_extra_length;

	/**
	 * Initializes the protocol for use.
	 *
	 * This process is run by the authenticator at power-on.
	 *
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*initialize)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Generates a fresh ECDH key agreement key pair (key_agreement_public_key, key_agreement_private_key).
	 *
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*regenerate)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Generates a fresh pinUvAuthToken.
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*reset_pin_uv_auth_token)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Encodes the current key_agreement_public_key as a COSE_Key object into the given CBOR stream.
	 *
	 * @param protocol the protocol
	 * @param encoder CBOR encoder
	 * @return a CTAP status code
	 * @retval CTAP1_ERR_OTHER when a CBOR encoding error occurs
	 * @retval CTAP2_OK when the COSE_Key was successfully encoded using the given CBOR encoder
	 */
	uint8_t (*get_public_key)(
		struct ctap_pin_protocol *protocol,
		CborEncoder *encoder
	);

	/**
	 * Processes the output of encapsulate from the peer and produces a shared secret,
	 * known to both platform and authenticator.
	 *
	 * In other words, it computes a shared key using the peer's public key (`peer_public_key`)
	 * and the authenticator's private key (`protocol.key_agreement_private_key`)
	 * using ECDH (Elliptic-curve Diffie-Hellman). It then derives the shared secret
	 * from the computed shared key (the exact algorithm varies between protocol versions).
	 *
	 * @param protocol this
	 * @param peer_public_key the public key of the peer (the platform, resp. the client),
	 * @param [out] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                            (32 bytes for v1, 64 bytes for v2)
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*decapsulate)(
		const struct ctap_pin_protocol *protocol,
		const COSE_Key *peer_public_key,
		uint8_t *shared_secret
	);

	/**
	 * Encrypts a plaintext using a shared secret as a key and outputs a ciphertext to the given ciphertext buffer.
	 *
	 * The plaintext remains unchanged.
	 *
	 * @param [in] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                           (32 bytes for v1, 64 bytes for v2)
	 * @param [in] plaintext the plaintext
	 * @param [in] plaintext_length the plaintext length in bytes
	 * @param [out] ciphertext the pointer to an array of size at least (plaintext_length + encryption_extra_length)
	 *                         bytes where the ciphertext will be written
	 * @retval 0 on success
	 * @retval 1 on error
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
	 * @param [in] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                           (32 bytes for v1, 64 bytes for v2)
	 * @param [in] ciphertext the ciphertext
	 * @param [in] ciphertext_length the ciphertext length in bytes
	 * @param [out] plaintext the pointer to an array of size at least (ciphertext_length - encryption_extra_length)
	 *                        bytes the plaintext will be written
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*decrypt)(
		const uint8_t *shared_secret,
		const uint8_t *ciphertext, const size_t ciphertext_length,
		uint8_t *plaintext
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * Uses a shared secret as the HMAC key.
	 *
	 * @param protocol the protocol
	 * @param ctx the pointer to the HMAC-256 context that will be initialized by this call
	 * @param shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                      (32 bytes for v1, 64 bytes for v2)
	 */
	void (*verify_init_with_shared_secret)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		const uint8_t *shared_secret
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * Uses the current pinUvAuthToken `protocol.pin_uv_auth_token` as the HMAC key.
	 * It also checks whether the pinUvAuthToken is in use or not.
	 * If the pinUvAuthToken is not in use, it returns an error.
	 *
	 * @param protocol the protocol
	 * @param ctx the pointer to the HMAC-256 context that will be initialized by this call
	 * @param pin_uv_auth_token_state the pinUvAuthToken state (if valid, i.e., in_use == true,
	 *        its usage_timer.last_use will be updated to the current time by this function)
	 * @retval 0 on success
	 * @retval 1 on error (the pinUvAuthToken is NOT in use)
	 */
	int (*verify_init_with_pin_uv_auth_token)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		ctap_pin_uv_auth_token_state *pin_uv_auth_token_state
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * This function might be called multiple times to pass the message in multiple chunks.
	 * When the message has zero length, this function does not have to be called at all
	 * (e.g., the following call sequence is completely correct: `verify_init_*() -> verify_final()`).
	 *
	 * @param protocol the protocol
	 * @param ctx the pointer to the HMAC-256 context
	 *            that has been already initialized by `verify_init_with_shared_secret()`
	 *            or `verify_init_with_pin_uv_auth_token()`
	 * @param message_data a chunk of the message
	 * @param message_data_length the size of the chunk of the message
	 */
	void (*verify_update)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		const uint8_t *message_data, const size_t message_data_length
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * This function must be called only after the context has been initialized by `verify_init_*()`
	 * and the message (if non-zero length) has been passed by one or more `verify_update()` calls.
	 *
	 * @param protocol the protocol
	 * @param ctx the pointer to the HMAC-256 context
	 *            that has been already initialized by `verify_init_with_shared_secret()`
	 *            or `verify_init_with_pin_uv_auth_token()`
	 * @param signature the signature
	 * @param signature_length the signature length in bytes
	 * @retval 0 on success (the signature matches the computed HMAC-256 digest),
	 * @retval 1 on error (invalid signature length or the signature does NOT match the computed HMAC-256 digest)
	 */
	int (*verify_final)(
		const struct ctap_pin_protocol *protocol,
		hmac_sha256_ctx_t *ctx,
		const uint8_t *signature, const size_t signature_length
	);

} ctap_pin_protocol_t;

typedef struct ctap_credentials_map_key {
	bool used;
	uint8_t rpId_hash[CTAP_SHA256_HASH_SIZE];
	uint8_t truncated;
	CTAP_rpId rpId;
	CTAP_userEntity user;
	uint8_t rpId_buffer[CTAP_RP_ID_MAX_SIZE];
	uint8_t userId_buffer[CTAP_USER_ENTITY_ID_MAX_SIZE];
	uint8_t userName_buffer[CTAP_USER_ENTITY_NAME_MAX_SIZE];
	uint8_t userDisplayName_buffer[CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE];
} ctap_credentials_map_key;
#define CTAP_truncated_rpId             (1u << 0)
#define CTAP_truncated_userName         (1u << 1)
#define CTAP_truncated_userDisplayName  (1u << 2)

typedef struct ctap_credentials_map_value {
	bool discoverable;
	uint32_t signCount;
	uint8_t id[128];
	// credProtect extension
	uint8_t credProtect;
	// the actual private key
	uint8_t private_key[32];
	// hmac-secret extension
	uint8_t CredRandomWithUV[32];
	uint8_t CredRandomWithoutUV[32];
} ctap_credentials_map_value;

typedef struct ctap_credential {
	ctap_credentials_map_key *key;
	ctap_credentials_map_value *value;
} ctap_credential;

typedef struct ctap_get_assertion_state {
	uint8_t client_data_hash[CTAP_SHA256_HASH_SIZE];
	uint8_t auth_data_rp_id_hash[CTAP_SHA256_HASH_SIZE];
	uint8_t auth_data_flags;
	size_t num_credentials;
	size_t next_credential_idx;
	ctap_credential credentials[128];
} ctap_get_assertion_state_t;

typedef enum ctap_stateful_command {
	CTAP_STATEFUL_CMD_NONE = 0,
	CTAP_STATEFUL_CMD_GET_ASSERTION = 1,
} ctap_stateful_command_t;

typedef struct ctap_stateful_command_state {
	// Note:
	//   To minimize RAM consumption, we leverage that the CTAP says:
	//     The authenticator MAY maintain state based on the assumption
	//     that each stateful command is exclusively preceded by either another instance
	//     of the same command, or by the corresponding state initializing command,
	//     and no more than 30 seconds will elapse between such commands. ...
	//     An authenticator MAY assume this globally, even when the transport-specific binding
	//     provides for independent streams of platform commands.
	//   Therefore, we use a union here (and one variable to identify which state, if any, is valid).

	ctap_stateful_command_t active_cmd;
	uint32_t last_cmd_time;
	union {
		ctap_get_assertion_state_t get_assertion;
	};

} ctap_stateful_command_state_t;

typedef struct ctap_state {

	ctap_persistent_state_t persistent;

	uint32_t last_cmd_time;

	ctap_response_t response;

	ctap_pin_protocol_t pin_protocol[1];
	uint8_t pin_boot_remaining_attempts;
	ctap_pin_uv_auth_token_state pin_uv_auth_token_state;

	ctap_stateful_command_state_t stateful_command_state;

} ctap_state_t;

typedef enum ctap_user_presence_result {
	CTAP_UP_RESULT_CANCEL,
	CTAP_UP_RESULT_TIMEOUT,
	CTAP_UP_RESULT_DENY,
	CTAP_UP_RESULT_ALLOW,
} ctap_user_presence_result_t;

// we internationally define the keepalive status codes
// to match the status codes defined in the CTAPHID layer (11.2.9.1.7. CTAPHID_KEEPALIVE (0x3B))
typedef enum LION_ATTR_PACKED ctap_keepalive_status {
	CTAP_STATUS_PROCESSING = 1,
	CTAP_STATUS_UPNEEDED = 2,
} ctap_keepalive_status_t;
static_assert(sizeof(ctap_keepalive_status_t) == 1, "sizeof(ctap_keepalive_status_t) == 1");

/**
 * Inform the CTAPHID layer about the current CTAP request (CTAPHID_CBOR message)
 * processing status.
 *
 * The CTAPHID layer must periodically send a CTAPHID_KEEPALIVE message while processing a CTAPHID_CBOR request.
 * See 11.2.9.1.7. CTAPHID_KEEPALIVE (0x3B)
 *   https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-keepalive
 * NOTE!
 *   There is a typo in the spec! The spec, even the latest iteration (as of 2025-04-22),
 *   CTAP 2.2 Proposed Standard from February 28, 2025, erroneously claims that CTAPHID_KEEPALIVE
 *   is only used with the CTAPHID_MSG command, when IN FACT it is only used with the CTAPHID_CBOR command.
 *   See the following message (and the corresponding thread) in the FIDO Dev (fido-dev) mailing list,
 *   where the typo is discussed and confirmed:
 *     https://groups.google.com/a/fidoalliance.org/g/fido-dev/c/HsGfTlbhQqY/m/3R1WPzzBAAAJ
 *
 * @param current_status the current status
 */
void ctap_send_keepalive_if_needed(ctap_keepalive_status_t current_status);

ctap_user_presence_result_t ctap_wait_for_user_presence(void);

uint32_t ctap_get_current_time(void);

uint8_t ctap_request(
	ctap_state_t *state,
	uint8_t cmd,
	size_t params_size,
	const uint8_t *params
);

void ctap_discard_stateful_command_state(ctap_state_t *state);

void ctap_update_stateful_command_timer(ctap_state_t *state);

void ctap_init(ctap_state_t *state);

void ctap_rng_reset(uint32_t seed);

int ctap_generate_rng(uint8_t *buffer, size_t length);

uint8_t ctap_get_info(ctap_state_t *state);

extern const uint8_t ctap_aaguid[CTAP_AAGUID_SIZE];

bool ctap_get_info_is_option_present(const ctap_state_t *state, uint32_t option);

bool ctap_get_info_is_option_present_with(const ctap_state_t *state, uint32_t option, bool value);

bool ctap_get_info_is_option_absent(const ctap_state_t *state, uint32_t option);

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length);

uint8_t ctap_get_pin_protocol(ctap_state_t *state, size_t protocol_version, ctap_pin_protocol_t **pin_protocol);

void ctap_pin_protocol_v1_init(ctap_pin_protocol_t *protocol);

void ctap_pin_uv_auth_token_begin_using(ctap_state_t *state, bool user_is_present, uint32_t permissions);

bool ctap_pin_uv_auth_token_check_usage_timer(ctap_state_t *state);

bool ctap_pin_uv_auth_token_get_user_present_flag_value(ctap_pin_uv_auth_token_state *token_state);

bool ctap_pin_uv_auth_token_get_user_verified_flag_value(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_clear_user_present_flag(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_clear_user_verified_flag(ctap_pin_uv_auth_token_state *token_state);

void ctap_pin_uv_auth_token_clear_permissions_except_lbw(ctap_pin_uv_auth_token_state *token_state);

bool ctap_pin_uv_auth_token_has_permissions(ctap_pin_uv_auth_token_state *token_state, uint32_t permissions);

void ctap_pin_uv_auth_token_stop_using(ctap_pin_uv_auth_token_state *token_state);

void ctap_convert_to_asn1_der_ecdsa_sig_value(
	const uint8_t *signature,
	uint8_t *asn1_der_signature,
	size_t *asn1_der_signature_size
);

void ctap_compute_rp_id_hash(uint8_t *rp_id_hash, const CTAP_rpId *rp_id);

void ctap_reset_credentials_store(void);

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length);

uint8_t ctap_get_assertion(ctap_state_t *state, const uint8_t *request, size_t length);

uint8_t ctap_get_next_assertion(ctap_state_t *state);

uint8_t ctap_reset(ctap_state_t *state);

uint8_t ctap_selection(ctap_state_t *state);

typedef bool (*ctap_truncate_str)(
	const ctap_string_t *str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_maybe_truncate_string(
	const ctap_string_t *input_str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_maybe_truncate_rp_id(
	const ctap_string_t *rp_id,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_store_arbitrary_length_string(
	const ctap_string_t *input_str,
	ctap_string_t *str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	ctap_truncate_str truncate_fn
);

#endif // LIONKEY_CTAP_H
