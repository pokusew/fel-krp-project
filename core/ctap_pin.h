#ifndef POKUSEW_CTAP_PIN_H
#define POKUSEW_CTAP_PIN_H

#include "ctap.h"
#include "ctap_parse.h"

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length);

void ctap_pin_protocol_v1_init(ctap_pin_protocol_t *protocol);


#endif // POKUSEW_CTAP_PIN_H
