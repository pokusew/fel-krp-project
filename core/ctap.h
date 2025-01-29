#ifndef POKUSEW_CTAP_H
#define POKUSEW_CTAP_H

#include "ctap_parse.h"
#include <cbor.h>

#define CTAP_CMD_MAKE_CREDENTIAL        0x01
#define CTAP_CMD_GET_ASSERTION          0x02
#define CTAP_CMD_GET_NEXT_ASSERTION     0x08
#define CTAP_CMD_GET_INFO               0x04
#define CTAP_CMD_CLIENT_PIN             0x06
#define CTAP_CMD_RESET                  0x07
#define CTAP_CMD_BIO_ENROLLMENT         0x09
#define CTAP_CMD_CREDENTIAL_MANAGEMENT  0x0A
#define CTAP_CMD_SELECTION              0x0B
#define CTAP_CMD_LARGE_BLOBS            0x0C
#define CTAP_CMD_CONFIG                 0x0D
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#commands
#define CTAP_VENDOR_FIRST           0x40
#define CTAP_VENDOR_LAST            0xBF


#define KEY_SPACE_BYTES     128
#define PIN_SALT_LEN        (32)

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
	uint8_t is_pin_set;
	uint8_t PIN_CODE_HASH[32];
	uint8_t PIN_SALT[PIN_SALT_LEN];
	int8_t pin_total_remaining_attempts;

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
	uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
	size_t length;
} ctap_response_t;

#define PIN_TOKEN_SIZE 16

typedef struct ctap_state {

	ctap_persistent_state_t persistent;

	ctap_response_t response;

	uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
	uint8_t KEY_AGREEMENT_PUB[64];
	uint8_t KEY_AGREEMENT_PRIV[32];
	int8_t pin_boot_remaining_attempts;

} ctap_state_t;

uint8_t ctap_request(
	ctap_state_t *state,
	uint16_t request_data_length,
	const uint8_t *request_data,
	uint8_t *response_status_code,
	uint16_t *response_data_length,
	uint8_t **response_data
);

void ctap_init(ctap_state_t *state);

#endif // POKUSEW_CTAP_H
