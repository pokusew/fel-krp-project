#include <string.h>
// #include <stdlib.h>
#include "ctap.h"
#include "utils.h"
#include "ctap_parse.h"

static void ctap_init_persistent_state_tmp(ctap_persistent_state_t *state) {

	debug_log("ctap_init_persistent_state_tmp" nl);

	// // set to 0xff instead of 0x00 to be easier on flash
	// memset(state, 0xff, sizeof(ctap_persistent_state_t));
	// // fresh RNG for key
	// ctap_generate_rng(state->master_keys, KEY_SPACE_BYTES);
	// debug_log("generated master_keys: ");
	// dump_hex(state->master_keys, KEY_SPACE_BYTES);

	// state->is_initialized = INITIALIZED_MARKER;

	state->pin_total_remaining_attempts = PIN_TOTAL_ATTEMPTS;

	// The default pre-configured minimum PIN length is at least 4 Unicode code points
	//   See 6.4. authenticatorGetInfo (0x04) minPINLength (0x0D)
	//     https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getinfo-minpinlength
	//   See also 6.5.1. PIN Composition Requirements
	//     https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-pin-composition
	state->pin_min_code_point_length = 4;

	state->is_pin_set = false;

	// state->num_rk_stored = 0;

	ctap_reset_credentials_store();

}

void ctap_all_pin_protocols_initialize(ctap_state_t *state) {
	const size_t num_pin_protocols = sizeof(state->pin_protocols) / sizeof(ctap_pin_protocol_t);
	for (size_t i = 0; i < num_pin_protocols; ++i) {
		ctap_pin_protocol_t *pin_protocol = &state->pin_protocols[i];

		assert(pin_protocol->version != 0);
		assert(pin_protocol->shared_secret_length != 0);

		assert(pin_protocol->crypto != NULL);

		assert(pin_protocol->initialize != NULL);
		assert(pin_protocol->regenerate != NULL);
		assert(pin_protocol->reset_pin_uv_auth_token != NULL);
		assert(pin_protocol->get_public_key != NULL);
		assert(pin_protocol->decapsulate != NULL);
		assert(pin_protocol->kdf != NULL);
		assert(pin_protocol->encrypt != NULL);
		assert(pin_protocol->decrypt != NULL);
		assert(pin_protocol->verify_get_context_size != NULL);
		assert(pin_protocol->verify_init_with_shared_secret != NULL);
		assert(pin_protocol->verify_init_with_pin_uv_auth_token != NULL);
		assert(pin_protocol->verify_update != NULL);
		assert(pin_protocol->verify_final != NULL);

		pin_protocol->initialize(pin_protocol); // TODO: handle error
	}
}

void ctap_all_pin_protocols_reset_pin_uv_auth_token(ctap_state_t *state) {
	const size_t num_pin_protocols = sizeof(state->pin_protocols) / sizeof(ctap_pin_protocol_t);
	for (size_t i = 0; i < num_pin_protocols; ++i) {
		ctap_pin_protocol_t *pin_protocol = &state->pin_protocols[i];
		pin_protocol->reset_pin_uv_auth_token(pin_protocol); // TODO: handle error
	}
	// If the pinUvAuthToken was "in use", this ensures that
	// all of the pinUvAuthToken's state variables are reset to their initial values
	// and MOST IMPORTANTLY any active stateful command state is discarded.
	ctap_pin_uv_auth_token_stop_using(state);
}

void ctap_init(ctap_state_t *state) {

	debug_log("ctap_init" nl);

	// TODO: Replace once proper persistence is implemented.
	ctap_init_persistent_state_tmp(&state->persistent);

	state->pin_boot_remaining_attempts = PIN_PER_BOOT_ATTEMPTS;

	// 6.5.5.1. Authenticator Configuration Operations Upon Power Up
	// At power-up, the authenticator calls initialize for each pinUvAuthProtocol that it supports.
	ctap_all_pin_protocols_initialize(state);

	if (state->persistent.is_pin_set) {
		info_log("pin remaining_tries=%" wPRId8 nl, state->persistent.pin_total_remaining_attempts);
	} else {
		info_log("pin not set" nl);
	}

}

static const ctap_command_handler_t ctap_command_handlers[] = {
	[CTAP_CMD_MAKE_CREDENTIAL] = ctap_make_credential,
	[CTAP_CMD_GET_ASSERTION] = ctap_get_assertion,
	[CTAP_CMD_GET_NEXT_ASSERTION] = ctap_get_next_assertion,
	[CTAP_CMD_GET_INFO] = ctap_get_info,
	[CTAP_CMD_CLIENT_PIN] = ctap_client_pin,
	[CTAP_CMD_RESET] = ctap_reset,
	[CTAP_CMD_CREDENTIAL_MANAGEMENT] = ctap_credential_management,
	[CTAP_CMD_SELECTION] = ctap_selection,
};
static const uint8_t ctap_command_handlers_num = sizeof(ctap_command_handlers) / sizeof(ctap_command_handler_t);
static_assert(
	sizeof(ctap_command_handlers) / sizeof(ctap_command_handler_t) == 12,
	"sizeof(ctap_command_handlers) / sizeof(ctap_command_handler) == 12"
);

ctap_command_handler_t ctap_get_command_handler(const uint8_t cmd) {
	// if the cmd value is out of bounds to be used as index for the ctap_command_handlers array
	if (cmd >= ctap_command_handlers_num) {
		return NULL;
	}
	// still, there might be a NULL at the cmd index in the ctap_command_handlers array
	return ctap_command_handlers[cmd];
}

#if LIONKEY_DEBUG_LEVEL > 0

static const ctap_string_t ctap_command_names[] = {
	[CTAP_CMD_MAKE_CREDENTIAL] = ctap_str_i("CTAP_CMD_MAKE_CREDENTIAL"),
	[CTAP_CMD_GET_ASSERTION] = ctap_str_i("CTAP_CMD_GET_ASSERTION"),
	[CTAP_CMD_GET_NEXT_ASSERTION] = ctap_str_i("CTAP_CMD_GET_NEXT_ASSERTION"),
	[CTAP_CMD_GET_INFO] = ctap_str_i("CTAP_CMD_GET_INFO"),
	[CTAP_CMD_CLIENT_PIN] = ctap_str_i("CTAP_CMD_CLIENT_PIN"),
	[CTAP_CMD_RESET] = ctap_str_i("CTAP_CMD_RESET"),
	[CTAP_CMD_CREDENTIAL_MANAGEMENT] = ctap_str_i("CTAP_CMD_CREDENTIAL_MANAGEMENT"),
	[CTAP_CMD_SELECTION] = ctap_str_i("CTAP_CMD_SELECTION"),
};
static const uint8_t ctap_command_names_num = sizeof(ctap_command_names) / sizeof(ctap_string_t);
static_assert(
	sizeof(ctap_command_names) / sizeof(ctap_string_t) == 12,
	"sizeof(ctap_command_names) / sizeof(ctap_string_t) == 12"
);

LION_ATTR_ALWAYS_INLINE static inline const ctap_string_t *ctap_get_command_name(const uint8_t cmd) {
	// if the cmd value is out of bounds to be used as index for the ctap_command_names array
	if (cmd >= ctap_command_names_num) {
		return NULL;
	}
	// still, there might be a NULL at the cmd index in the ctap_command_names array
	return &ctap_command_names[cmd];
}

LION_ATTR_ALWAYS_INLINE static inline void ctap_debug_log_command_name(const uint8_t cmd) {
	const ctap_string_t *const cmd_name = ctap_get_command_name(cmd);
	if (cmd_name != NULL) {
		debug_log(magenta("%.*s") nl, (int) cmd_name->size, cmd_name->data);
	} else {
		debug_log(magenta("unknown command name, cmd = %" PRIu8) nl, cmd);
	}
}

#endif

LION_ATTR_ALWAYS_INLINE static inline bool ctap_discard_stateful_command_state_if_expired(ctap_state_t *const state) {
	// The CTAP_STATEFUL_CMD_GET_ASSERTION state MUST be discarded if the timer since the last call to
	// authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30 seconds.
	// For the other stateful commands, this timer-based state expiration is OPTIONAL (MAY).
	// However, we implemented the expiration here centrally for all stateful commands
	// to simplify their implementation. In case, this central check were to be removed,
	// we would have to implement an explicit check at least in ctap_get_next_assertion().
	if (ctap_has_stateful_command_state(state)) {
		const uint32_t elapsed_ms_since_last_cmd = state->current_time - state->stateful_command_state.last_cmd_time;
		if (elapsed_ms_since_last_cmd > (30 * 1000)) {
			debug_log(
				red("discarding the state of the stateful command %d because more than 30 seconds elapsed"
					"since the last corresponding command") nl,
				state->stateful_command_state.active_cmd
			);
			ctap_discard_stateful_command_state(state);
			return true;
		}
	}
	return false;
}

LION_ATTR_ALWAYS_INLINE static inline uint8_t ctap_invoke_handler(
	ctap_state_t *const state,
	const uint8_t cmd,
	const size_t params_size,
	const uint8_t *params,
	ctap_response_t *const response
) {

	uint8_t status;

	ctap_command_handler_t handler = ctap_get_command_handler(cmd);

	// initially, set the response length to 0 (to simplify the code below)
	// - on success (CTAP2_OK), it is set to the actual response length
	// - otherwise, it remains set to 0 (error responses cannot have any data)
	response->length = 0;

	if (handler == NULL) {
		error_log(red("error: invalid cmd: 0x%02" wPRIx8) nl, cmd);
		return CTAP1_ERR_INVALID_COMMAND;
	}

	if_debug(ctap_debug_log_command_name(cmd));

	// prepare the response CBOR encoder
	CborEncoder response_encoder;
	cbor_encoder_init(&response_encoder, response->data, response->data_max_size, 0);

	// initialize the params CBOR parser if a non-zero length params is passed
	CborParser params_parser;
	CborValue params_it;
	CborValue *params_it_ptr = NULL;
	if (params_size > 0) {
		// ctap_init_cbor_parser() might immediately return CTAP2_ERR_INVALID_CBOR
		// if the params' first byte(s) are not a valid CBOR
		status = ctap_init_cbor_parser(params, params_size, &params_parser, &params_it);
		if (status != CTAP2_OK) {
			return status;
		}
		params_it_ptr = &params_it;
	}

	// Note that some commands do not take any input parameters at all.
	// Their corresponding handlers completely ignore the params (CborValue *it) argument.
	// This is probably the best future-proof behavior, similar to the ignoring
	// of any individual unexpected parameter names within the params CBOR map.
	// Note that the params argument (CborValue *it) might be NULL if no params are present.
	// The handlers MUST handle that correctly (e.g., return an CTAP2_ERR_MISSING_PARAMETER error
	// if the command takes input parameters but the params argument is NULL).
	status = handler(state, params_it_ptr, &response_encoder);

	// only success responses have data
	if (status == CTAP2_OK) {
		response->length = cbor_encoder_get_buffer_size(&response_encoder, response->data);
	}

	return status;

}

/**
 * Processes a CTAP2 command, updates the CTAP state, and returns a response
 * (a CTAP status code + CBOR-encoded response data)
 *
 * @param [in,out] state the current CTAP state, will be updated
 * @param [in] cmd the CTAP2 command code
 * @param [in] params_size the size of the params byte array, might be 0, if there are no params
 * @param [in] params a byte array of params_size length, the command parameters encoded as CBOR,
 *                    MUST NOT be NULL iff params_size > 0, i.e., NULL is allowed iff params_size == 0
 * @param [in,out] response The response.data field must point to a non-null buffer
 *                          of response.data_max_size (> 0) bytes.
 *                          Upon return, the response.length will be set to the number of bytes of the CBOR-encoded
 *                          response bytes that were written to the response.data.
 *                          The following holds: 0 <= response.length <= response.data_max_size.
 *                          If the response cannot fit into the given buffer,
 *                          the CTAP1_ERR_OTHER error is returned (see cbor_encoding_check(),
 *                          and the response.length is set to 0 (note that the response.data might contain partially
 *                          written response, up to the response.data_max_size bytes).
 *
 * @return a CTAP status code
 * @retval CTAP2_OK if the command was processed successfully
 * @retval a CTAP error code if the command was NOT processed successfully
 */
uint8_t ctap_request(
	ctap_state_t *const state,
	const uint8_t cmd,
	const size_t params_size,
	const uint8_t *params,
	ctap_response_t *const response
) {

	assert(state != NULL);
	assert(params_size == 0 || params != NULL);
	assert(response != NULL && response->data != NULL && response->data_max_size != 0);

	// get the current time once at the beginning of the command processing
	// to have one constant value throughout the whole command processing
	state->current_time = ctap_get_current_time();

	info_log("ctap_request cmd=0x%02" wPRIx8 " params_size=%" PRIsz nl, cmd, params_size);
	if (params_size > 0) {
		dump_hex(params, params_size);
	}

	ctap_pin_uv_auth_token_check_usage_timer(state);

	ctap_discard_stateful_command_state_if_expired(state);

	uint8_t status = ctap_invoke_handler(state, cmd, params_size, params, response);

	if (LIONKEY_DEBUG_LEVEL > 1) {
		uint32_t duration = ctap_get_current_time() - state->current_time;
		if (status == CTAP2_OK) {
			info_log(
				green(
					"ctap_request: response status code"
					" 0x%02" wPRIx8 " in %" PRId32 " ms, response length %" PRIsz " bytes") nl,
				status, duration, response->length
			);
			dump_hex(response->data, response->length);
		} else {
			info_log(
				red("ctap_request: error response status code 0x%02" wPRIx8 " in %" PRId32 " ms") nl,
				status, duration
			);
		}
	}

	return status;

}

void ctap_discard_stateful_command_state(ctap_state_t *state) {
	// avoid unnecessary memset() calls
	// Our code implementation guarantees that the WHOLE stateful_command_state is zeroed
	// iff (if and only if) stateful_command_state.active_cmd == CTAP_STATEFUL_CMD_NONE.
	if (!ctap_has_stateful_command_state(state)) {
		return;
	}
	static_assert(
		CTAP_STATEFUL_CMD_NONE == 0,
		"CTAP_STATEFUL_CMD_NONE must be 0,"
		" so that memset(stateful_command_state, 0, sizeof(ctap_stateful_command_state_t))"
		" can be used in ctap_discard_stateful_command_state()."
	);
	memset(&state->stateful_command_state, 0, sizeof(state->stateful_command_state));
	// Note:
	//   We could just set the stateful_command_state.active_cmd to CTAP_STATEFUL_CMD_NONE,
	//   and leave the rest of the state in memory. However, as a good practice, we want to avoid
	//   keeping any potentially sensitive state in memory longer than necessary.
}

void ctap_update_stateful_command_timer(ctap_state_t *state) {
	assert(ctap_has_stateful_command_state(state));
	state->stateful_command_state.last_cmd_time = state->current_time;
}
