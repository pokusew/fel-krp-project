#include <string.h>
#include <stdlib.h>
#include "ctap.h"
#include "utils.h"
#include "ctap_pin.h"
#include <uECC.h>

int ctap_generate_rng(uint8_t *buffer, size_t length) {
	debug_log("ctap_generate_rng: %zu bytes to %p" nl, length, buffer);
	for (size_t i = 0; i < length; i++) {
		buffer[i] = (uint8_t) rand();
	}
	return 1;
}

static void ctap_state_init(ctap_persistent_state_t *state) {

	debug_log("ctap_state_init" nl);

	// set to 0xff instead of 0x00 to be easier on flash
	memset(state, 0xff, sizeof(ctap_persistent_state_t));
	// fresh RNG for key
	ctap_generate_rng(state->master_keys, KEY_SPACE_BYTES);
	debug_log("generated master_keys: ");
	dump_hex(state->master_keys, KEY_SPACE_BYTES);

	state->is_initialized = INITIALIZED_MARKER;
	state->pin_total_remaining_attempts = PIN_TOTAL_ATTEMPTS;
	state->is_pin_set = 0;
	state->num_rk_stored = 0;

	// ctap_reset_rk();

}

void authenticator_write_state(ctap_state_t *state) {

}

void ctap_init(ctap_state_t *state) {

	printf("ctap_init" nl);

	// crypto_ecc256_init();
	uECC_set_rng((uECC_RNG_Function) ctap_generate_rng);

	// int is_init = authenticator_read_state(&state);

	// device_set_status(CTAPHID_STATUS_IDLE);

	// if (false) {
	// 	printf(
	// 		"auth state is initialized" nl
	// 		"  is_pin_set = %" wPRIu8 nl
	// 		"  remaining_tries = %" wPRId8 nl
	// 		"  num_rk_stored = %" PRIu16 nl
	// 		"  is_initialized = 0x%08" PRIx32 nl
	// 		"  is_invalid = 0x%08" PRIx32 nl,
	// 		state.is_pin_set,
	// 		state.remaining_tries,
	// 		state.num_rk_stored,
	// 		state.is_initialized,
	// 		state.is_invalid
	// 	);
	// 	debug_log("  master_keys = ");
	// 	dump_hex(state->persistent.master_keys, KEY_SPACE_BYTES);
	// 	debug_log("  PIN_SALT = ");
	// 	dump_hex(state->persistent.PIN_SALT, sizeof(state->persistent.PIN_SALT));
	// } else {
		ctap_state_init(&state->persistent);
		authenticator_write_state(state);
	// }

	state->pin_boot_remaining_attempts = PIN_PER_BOOT_ATTEMPTS;

	// 6.5.5.1. Authenticator Configuration Operations Upon Power Up
	// At power-up, the authenticator calls initialize for each pinUvAuthProtocol that it supports.
	ctap_pin_protocol_v1_init(&state->pin_protocol[0]);

	// do_migration_if_required(&state);

	// crypto_load_master_secret(state->persistent->master_keys);

	if (state->persistent.is_pin_set) {
		info_log("pin remaining_tries=%" wPRId8 nl, state->persistent.pin_total_remaining_attempts);
	} else {
		info_log("pin not set" nl);
	}

}

uint8_t ctap_request(
	ctap_state_t *state,
	uint16_t request_data_length,
	const uint8_t *request_data,
	uint8_t *response_status_code,
	uint16_t *response_data_length,
	uint8_t **response_data
) {

	CborEncoder *encoder = &state->response.encoder;

	uint8_t status = 0;
	uint8_t cmd = *request_data;
	request_data++;
	request_data_length--;

	cbor_encoder_init(encoder, state->response.data, sizeof(state->response.data), 0);

	debug_log("cbor input structure: %d bytes" nl, request_data_length);
	debug_log("cbor req: ");
	dump_hex(request_data, request_data_length);

	switch (cmd) {
		case CTAP_CMD_CLIENT_PIN:
			info_log(magenta("CTAP_CLIENT_PIN") nl);
			status = ctap_client_pin(state, request_data, request_data_length);
			break;
		default:
			status = CTAP1_ERR_INVALID_COMMAND;
			error_log(red("error: invalid cmd: 0x%02" wPRIx8) nl, cmd);
	}

	if (status == CTAP2_OK) {
		state->response.length = cbor_encoder_get_buffer_size(encoder, state->response.data);
	}else {
		state->response.length = 0;
	}

	debug_log(
		"cbor output structure length %zu bytes, status code 0x%02" wPRIx8 nl,
		state->response.length,
		status
	);

	*response_status_code = status;
	*response_data = state->response.data;
	*response_data_length = state->response.length;

	// TODO: return value is no longer used (status code is returned via the response_status_code reference)
	return status;

}
