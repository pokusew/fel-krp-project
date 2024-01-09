#ifndef FIDO2_STORAGE_H
#define FIDO2_STORAGE_H

#include "ctap.h"

#define KEY_SPACE_BYTES     128
#define PIN_SALT_LEN        (32)

#define EMPTY_MARKER        0xFF
#define INITIALIZED_MARKER  0xA5
#define INVALID_MARKER      0xDD

typedef struct {

	// PIN information
	uint8_t is_pin_set;
	uint8_t PIN_CODE_HASH[32];
	uint8_t PIN_SALT[PIN_SALT_LEN];
	int8_t remaining_tries;

	// number of stored client-side discoverable credentials
	// aka resident credentials aka resident keys (RK)
	uint16_t num_rk_stored;

	// master keys data
	uint8_t master_keys[KEY_SPACE_BYTES];

	uint32_t is_invalid;
	// note: in order for the data loss prevention logic to work, is_initialized must be the last field
	uint32_t is_initialized;

} AuthenticatorState;

extern AuthenticatorState STATE;

#endif // FIDO2_STORAGE_H
