#ifndef LIONKEY_CTAP_H
#define LIONKEY_CTAP_H

#ifndef LIONKEY_DEVELOPMENT_OVERRIDE
	#define LIONKEY_DEVELOPMENT_OVERRIDE 0
#endif

#include "ctap_parse.h"
#include "ctap_crypto.h"
#include "ctap_asn1.h"
#include "ctap_pin_protocol.h"
#include "compiler.h"

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

#define CTAP_PIN_HASH_SIZE  16

// 6.5.2.2. PIN-Entry and User Verification Retries Counters
//   * Authenticators MUST allow no more than 8 retries but MAY set a lower maximum.
//   * Each correct PIN entry resets the pinRetries and the uvRetries counters back
//     to their maximum values unless the PIN is already disabled.
//   * Each incorrect PIN entry decrements the pinRetries by 1.
//   * Once the pinRetries counter reaches 0, both ClientPin as well as built-in user verification.
//     are disabled and can only be enabled if authenticator is reset
//     (during reset, all data from the persistent memory are wiped).
#define CTAP_PIN_TOTAL_ATTEMPTS     8
// 6.5.5.6. Changing existing PIN
// 6.5.5.7.1. Getting pinUvAuthToken using getPinToken (superseded)
// 6.5.5.7.2. Getting pinUvAuthToken using getPinUvAuthTokenUsingPinWithPermissions (ClientPIN)
//   If the authenticator sees 3 consecutive mismatches, it returns CTAP2_ERR_PIN_AUTH_BLOCKED,
//   indicating that power cycling is needed for further operations.
//   This is done so that malware running on the platform should not be able to block
//   the device without user interaction.
#define CTAP_PIN_PER_BOOT_ATTEMPTS  3
static_assert(
	CTAP_PIN_PER_BOOT_ATTEMPTS < CTAP_PIN_TOTAL_ATTEMPTS,
	"CTAP_PIN_PER_BOOT_ATTEMPTS must be greater than or equal to CTAP_PIN_PER_BOOT_ATTEMPTS"
);

typedef struct ctap_persistent_state {

	// PIN information
	uint8_t pin_min_code_point_length;
	bool is_pin_set;
	// from the spec we can derive that 4 <= pin_code_point_length <= 63
	uint8_t pin_code_point_length;
	uint8_t pin_hash[CTAP_PIN_HASH_SIZE];
	uint8_t pin_total_remaining_attempts;

} ctap_persistent_state_t;

#define CTAP_RESPONSE_BUFFER_SIZE   4096

typedef struct ctap_response {
	size_t length;
	const size_t data_max_size;
	uint8_t *const data;
} ctap_response_t;

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

typedef struct cred_mgmt_enumerate_rps_state {
	size_t num_rps;
	size_t next_rp_idx;
	CTAP_rpId *rp_ids[128];
} cred_mgmt_enumerate_rps_state_t;

typedef struct cred_mgmt_enumerate_credentials_state {
	size_t num_credentials;
	size_t next_credential_idx;
	ctap_credential credentials[128];
} cred_mgmt_enumerate_credentials_state_t;

typedef enum ctap_stateful_command {
	CTAP_STATEFUL_CMD_NONE = 0,
	CTAP_STATEFUL_CMD_GET_ASSERTION = 1,
	CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_RPS = 2,
	CTAP_STATEFUL_CMD_CRED_MGMT_ENUMERATE_CREDENTIALS = 3,
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
		cred_mgmt_enumerate_rps_state_t cred_mgmt_enumerate_rps;
		cred_mgmt_enumerate_credentials_state_t cred_mgmt_enumerate_credentials;
	};

} ctap_stateful_command_state_t;

typedef struct ctap_state {

	const ctap_crypto_t *const crypto;

	ctap_persistent_state_t persistent;

	uint32_t init_time;
	uint32_t current_time;

	ctap_pin_protocol_t pin_protocols[2];
	uint8_t pin_boot_remaining_attempts;
	ctap_pin_uv_auth_token_state pin_uv_auth_token_state;

	ctap_stateful_command_state_t stateful_command_state;

} ctap_state_t;

LION_ATTR_ALWAYS_INLINE static inline bool ctap_has_stateful_command_state(const ctap_state_t *const state) {
	return state->stateful_command_state.active_cmd != CTAP_STATEFUL_CMD_NONE;
}

#define CTAP_PIN_PROTOCOLS_CONST_INIT(crypto_ptr) \
    { \
        CTAP_PIN_PROTOCOL_V1_CONST_INIT(crypto_ptr), \
        CTAP_PIN_PROTOCOL_V2_CONST_INIT(crypto_ptr), \
    }

#define CTAP_STATE_CONST_INIT(crypto_ptr) \
    { \
        .crypto = (crypto_ptr), \
        .pin_protocols = CTAP_PIN_PROTOCOLS_CONST_INIT(crypto_ptr), \
    }

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

typedef uint8_t (*ctap_command_handler_t)(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

static_assert(
	sizeof(ctap_command_handler_t) == sizeof(void *),
	"sizeof(ctap_command_handler) == sizeof(void *)"
);

ctap_command_handler_t ctap_get_command_handler(uint8_t cmd);

uint8_t ctap_request(
	ctap_state_t *state,
	uint8_t cmd,
	size_t params_size,
	const uint8_t *params,
	ctap_response_t *response
);

void ctap_discard_stateful_command_state(ctap_state_t *state);

void ctap_update_stateful_command_timer(ctap_state_t *state);

void ctap_init(ctap_state_t *state);

void ctap_all_pin_protocols_initialize(ctap_state_t *state);

void ctap_all_pin_protocols_reset_pin_uv_auth_token(ctap_state_t *state);

uint8_t ctap_get_info(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

extern const uint8_t ctap_aaguid[CTAP_AAGUID_SIZE];

bool ctap_get_info_is_option_present(const ctap_state_t *state, uint32_t option);

bool ctap_get_info_is_option_present_with(const ctap_state_t *state, uint32_t option, bool value);

bool ctap_get_info_is_option_absent(const ctap_state_t *state, uint32_t option);

uint8_t ctap_client_pin(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_get_pin_protocol(ctap_state_t *state, size_t protocol_version, ctap_pin_protocol_t **pin_protocol);

void ctap_pin_uv_auth_token_begin_using(ctap_state_t *state, bool user_is_present, uint32_t permissions);

bool ctap_pin_uv_auth_token_check_usage_timer(ctap_state_t *state);

bool ctap_pin_uv_auth_token_get_user_present_flag_value(const ctap_state_t *state);

bool ctap_pin_uv_auth_token_get_user_verified_flag_value(const ctap_state_t *state);

void ctap_pin_uv_auth_token_clear_user_present_flag(ctap_state_t *state);

void ctap_pin_uv_auth_token_clear_user_verified_flag(ctap_state_t *state);

void ctap_pin_uv_auth_token_clear_permissions_except_lbw(ctap_state_t *state);

bool ctap_pin_uv_auth_token_has_permissions(const ctap_state_t *state, uint32_t permissions);

void ctap_pin_uv_auth_token_stop_using(ctap_state_t *state);

void ctap_compute_rp_id_hash(const ctap_crypto_t *crypto, uint8_t *rp_id_hash, const CTAP_rpId *rp_id);

size_t ctap_get_num_stored_credentials(void);

size_t ctap_get_num_stored_discoverable_credentials(void);

size_t ctap_get_num_max_possible_remaining_discoverable_credentials(void);

ctap_credentials_map_key *ctap_get_credential_key_by_idx(int idx);

ctap_credentials_map_value *ctap_get_credential_value_by_idx(int idx);

bool ctap_credential_matches_rp_id_hash(
	const ctap_credentials_map_key *key,
	const uint8_t *rp_id_hash
);

bool ctap_credential_matches_rp(
	const ctap_credentials_map_key *key,
	const CTAP_rpId *rp_id
);

int ctap_find_credential_index(
	const CTAP_rpId *rp_id,
	const CTAP_userHandle *user_handle
);

int ctap_lookup_credential_by_desc(const CTAP_credDesc *cred_desc);

uint8_t ctap_store_credential(
	const CTAP_rpId *rp_id,
	const CTAP_userEntity *user,
	const ctap_credentials_map_value *credential
);

uint8_t ctap_delete_credential(int idx);

void ctap_reset_credentials_store(void);

bool ctap_should_add_credential_to_list(
	const ctap_credentials_map_value *cred_value,
	bool is_from_allow_list,
	bool response_has_uv
);

uint8_t ctap_find_discoverable_credentials_by_rp_id(
	const CTAP_rpId *rp_id,
	const uint8_t *rp_id_hash,
	bool response_has_uv,
	ctap_credential *credentials,
	size_t *num_credentials,
	size_t max_num_credentials
);

uint8_t ctap_enumerate_rp_ids_of_discoverable_credentials(
	CTAP_rpId **rp_ids,
	size_t *num_rp_ids,
	size_t max_num_rp_ids
);

uint8_t ctap_make_credential(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_get_assertion(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_get_next_assertion(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_reset(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_credential_management(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_selection(ctap_state_t *state, CborValue *it, CborEncoder *encoder);

uint8_t ctap_encode_ctap_string_as_byte_string(
	CborEncoder *encoder,
	const ctap_string_t *str
);

uint8_t ctap_encode_ctap_string_as_text_string(
	CborEncoder *encoder,
	const ctap_string_t *str
);

uint8_t ctap_encode_public_key(
	CborEncoder *encoder,
	const uint8_t *public_key
);

uint8_t ctap_encode_pub_key_cred_desc(
	CborEncoder *encoder,
	size_t cred_id_size,
	const uint8_t *cred_id_data
);

uint8_t ctap_encode_pub_key_cred_user_entity(
	CborEncoder *encoder,
	const CTAP_userEntity *user,
	bool include_user_identifiable_info
);

uint8_t ctap_encode_rp_entity(
	CborEncoder *encoder,
	const CTAP_rpId *rp_id
);

#endif // LIONKEY_CTAP_H
