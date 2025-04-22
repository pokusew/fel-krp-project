#include <string.h>
// #include <stdlib.h>
#include "ctap.h"
#include "utils.h"
#include "ctap_parse.h"
#include <uECC.h>

// int ctap_generate_rng(uint8_t *buffer, size_t length) {
// 	debug_log("ctap_generate_rng: %zu bytes to %p" nl, length, buffer);
// 	for (size_t i = 0; i < length; i++) {
// 		buffer[i] = (uint8_t) rand();
// 	}
// 	return 1;
// }

bool ctap_rp_id_matches(const CTAP_rpId *rp_id_a, const CTAP_rpId *rp_id_b) {
	const size_t size = rp_id_a->id_size;
	if (size != rp_id_b->id_size) {
		return false;
	}
	return memcmp(rp_id_a->id, rp_id_b->id, size) == 0;
}

bool ctap_user_handle_matches(const CTAP_userHandle *handle_a, const CTAP_userHandle *handle_b) {
	const size_t size = handle_a->id_size;
	if (size != handle_b->id_size) {
		return false;
	}
	return memcmp(handle_a->id, handle_b->id, size) == 0;
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

	debug_log("ctap_init" nl);

	// crypto_ecc256_init();
	uECC_set_rng((uECC_RNG_Function) ctap_generate_rng);

	// int is_init = authenticator_read_state(&state);

	// device_set_status(CTAPHID_STATUS_IDLE);

	// if (false) {
	// 	debug_log(
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
	uint8_t cmd,
	size_t params_size,
	const uint8_t *params
) {

	CborEncoder *encoder = &state->response.encoder;

	uint8_t status;

	cbor_encoder_init(encoder, state->response.data, sizeof(state->response.data), 0);

	error_log("ctap_request cmd=0x%02" wPRIx8 " params_size=%" PRIsz nl, cmd, params_size);
	dump_hex(params, params_size);

	switch (cmd) {
		case CTAP_CMD_MAKE_CREDENTIAL:
			info_log(magenta("CTAP_CMD_MAKE_CREDENTIAL") nl);
			status = ctap_make_credential(state, params, params_size);
			break;
		case CTAP_CMD_GET_INFO:
			info_log(magenta("CTAP_CMD_GET_INFO") nl);
			// Consider returning an error (e.g., CTAP1_ERR_INVALID_PARAMETER)
			// if any input parameters are provided (because the authenticatorGetInfo command does not
			// take any inputs parameters). Currently, we ignore any unexpected parameters.
			status = ctap_get_info(state);
			break;
		case CTAP_CMD_CLIENT_PIN:
			info_log(magenta("CTAP_CLIENT_PIN") nl);
			status = ctap_client_pin(state, params, params_size);
			break;
		case CTAP_CMD_RESET:
			info_log(magenta("CTAP_CMD_RESET") nl);
			// Consider returning an error (e.g., CTAP1_ERR_INVALID_PARAMETER)
			// if any input parameters are provided (because the authenticatorGetInfo command does not
			// take any inputs parameters). Currently, we ignore any unexpected parameters.
			status = ctap_reset(state);
			break;
		case CTAP_CMD_SELECTION:
			info_log(magenta("CTAP_CMD_SELECTION") nl);
			// Consider returning an error (e.g., CTAP1_ERR_INVALID_PARAMETER)
			// if any input parameters are provided (because the authenticatorSelection command does not
			// take any inputs parameters). Currently, we ignore any unexpected parameters.
			status = ctap_selection(state);
			break;
		default:
			status = CTAP1_ERR_INVALID_COMMAND;
			error_log(red("error: invalid cmd: 0x%02" wPRIx8) nl, cmd);
	}

	if (status == CTAP2_OK) {
		state->response.length = cbor_encoder_get_buffer_size(encoder, state->response.data);
	} else {
		state->response.length = 0;
	}

	if (status == CTAP2_OK) {
		debug_log(
			green("ctap_request: response status code 0x%02" wPRIx8 ", response length %" PRIsz " bytes") nl,
			status,
			state->response.length
		);
		dump_hex(state->response.data, state->response.length);
	} else {
		debug_log(red("ctap_request: error response status code 0x%02" wPRIx8) nl, status);
	}

	return status;

}
