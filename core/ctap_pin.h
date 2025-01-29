#ifndef POKUSEW_CTAP_PIN_H
#define POKUSEW_CTAP_PIN_H

#include "ctap.h"
#include "ctap_parse.h"

typedef struct CTAP_pinUvAuthToken {
	int rpId;
	bool rpIdSet;
	int permissions;
	// usage timer
	bool in_use;
	// initial usage time limit
	// user present time limit
	// max usage time period
	bool user_verified;
	bool user_present;
} CTAP_pinUvAuthToken;

typedef struct CTAP_pinState {
	bool is_pin_set;
	// uint8_t PIN_CODE_HASH[32];
	// uint8_t PIN_SALT[PIN_SALT_LEN];
	uint8_t remaining_tries;
} CTAP_pinState;

// PIN information

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length);


#endif // POKUSEW_CTAP_PIN_H
