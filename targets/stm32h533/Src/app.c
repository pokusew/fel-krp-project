#include "app.h"
#include "usb.h"
#include "main.h"
#include "utils.h"
#include <stdbool.h>
#include "tusb.h"
#include "ctap_crypto_software.h"
#include "hw_crypto.h"
#include "app_test.h"

// supported using UART debug chars:
// l - toggle the Blue LED

// LED status indicators:
// Green  main loop running

static ctap_software_crypto_context_t app_crypto_ctx;
const ctap_crypto_t app_sw_crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&app_crypto_ctx);

static stm32h533_crypto_context_t app_hw_crypto_ctx;
const ctap_crypto_t app_hw_crypto = STM32H533_CRYPTO_CONST_INIT(&app_hw_crypto_ctx);

ctaphid_state_t app_ctaphid;
static const uint8_t app_ctaphid_capabilities =
	CTAPHID_CAPABILITY_WINK | CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG;
static const uint8_t app_ctaphid_version_major = 1;
static const uint8_t app_ctaphid_version_minor = 1;
static const uint8_t app_ctaphid_version_build = 0;
static uint8_t app_ctaphid_cbor_response_buffer[1 + 4096];
ctap_response_t app_ctap_response = {
	.data_max_size = sizeof(app_ctaphid_cbor_response_buffer) - 1,
	.data = &app_ctaphid_cbor_response_buffer[1]
};
ctap_state_t app_ctap = CTAP_STATE_CONST_INIT(&app_hw_crypto);

static inline void app_hid_task(void) {
	tud_task(); // tinyusb device task
	app_hid_report_send_queue_send_one_if_possible();
}

static ctap_keepalive_status_t app_ctap_last_status = CTAP_STATUS_PROCESSING;
static uint32_t app_ctap_last_status_message_timestamp = 0;

static inline void app_ctap_reset_keepalive(void) {
	app_ctap_last_status = CTAP_STATUS_PROCESSING;
	app_ctap_last_status_message_timestamp = 0;
}

static void app_ctaphid_send_keepalive(ctap_keepalive_status_t status) {
	// debug_log("sending CTAPHID_KEEPALIVE" nl);
	assert(ctaphid_has_complete_message_ready(&app_ctaphid));
	const ctaphid_channel_buffer_t *message = &app_ctaphid.buffer;
	ctaphid_packet_t res;
	ctaphid_create_init_packet(&res, message->cid, CTAPHID_KEEPALIVE, 1);
	res.pkt.init.payload[0] = status;
	app_hid_report_send_queue_add(&res);
	app_ctap_last_status_message_timestamp = HAL_GetTick();
}

void ctap_send_keepalive_if_needed(ctap_keepalive_status_t current_status) {

	// send immediately whenever the status changes
	if (current_status != app_ctap_last_status) {
		app_ctap_last_status = current_status;
		app_ctaphid_send_keepalive(current_status);
		return;
	}

	// but at least every 100ms
	uint32_t elapsed_since_last_keepalive = HAL_GetTick() - app_ctap_last_status_message_timestamp;
	// use a smaller value here to guarantee that the keepalive messages are sent frequently enough
	// even if ctap_send_keepalive_if_needed() is sometimes invoked late
	if (elapsed_since_last_keepalive > 80) {
		app_ctaphid_send_keepalive(current_status);
	}

}

ctap_user_presence_result_t ctap_wait_for_user_presence(void) {

	info_log(yellow("waiting for user presence (press the ") cyan("BLUE") yellow(" button) ...") nl);
	ctap_send_keepalive_if_needed(CTAP_STATUS_UPNEEDED);

	const uint32_t timeout_ms = 30 * 1000; // 30 seconds
	uint32_t start_timestamp = HAL_GetTick();

	if (BspButtonState == BUTTON_PRESSED) {
		BspButtonState = BUTTON_RELEASED;
	}

	while (true) {
		app_hid_task();
		if (app_ctaphid.buffer.cancel) {
			info_log(yellow("ctap_wait_for_user_presence: ") red("got CANCEL via CTAPHID") nl);
			return CTAP_UP_RESULT_CANCEL;
		}
		uint32_t elapsed_ms = HAL_GetTick() - start_timestamp;
		if (elapsed_ms > timeout_ms) {
			info_log(yellow("ctap_wait_for_user_presence: ") red("TIMEOUT") nl);
			return CTAP_UP_RESULT_TIMEOUT;
		}
		if (BspButtonState == BUTTON_PRESSED) {
			BspButtonState = BUTTON_RELEASED;
			info_log(yellow("ctap_wait_for_user_presence: ") green("ALLOW") nl);
			return CTAP_UP_RESULT_ALLOW;
		}
		ctap_send_keepalive_if_needed(CTAP_STATUS_UPNEEDED);
	}

}

uint32_t ctap_get_current_time(void) {
	return HAL_GetTick();
}

static void handle_packet_using_send_or_queue_ctaphid_packet(const ctaphid_packet_t *packet, void *ctx) {
	UNUSED(ctx);
	app_hid_report_send_queue_add(packet);
}

noreturn void app_run(void) {

	info_log(nl nl cyan("app_run") nl);

	BSP_LED_On(LED_GREEN);

	uint32_t t1 = HAL_GetTick();

	ctaphid_init(&app_ctaphid);
	if (app_sw_crypto.init(&app_sw_crypto, 0) != CTAP_CRYPTO_OK) {
		Error_Handler();
	}
	if (app_hw_crypto.init(&app_hw_crypto, 0) != CTAP_CRYPTO_OK) {
		Error_Handler();
	}
	ctap_init(&app_ctap);

	uint32_t t2 = HAL_GetTick();

	info_log("init done in %" PRId32 " ms" nl, t2 - t1);

	usb_init();

	int debug_uart_rx;

	uint32_t message_wait_time_start = 0;
	ctaphid_packet_t res;

	while (true) {

		app_hid_task();

		if ((debug_uart_rx = Debug_UART_Get_Byte()) != -1) {

			debug_log("debug_uart_rx = %c" nl, debug_uart_rx);

			if (debug_uart_rx == 'l') {

				BSP_LED_Toggle(LED_GREEN);

			} else if (debug_uart_rx == 'r') {

				app_test_rng_tinymt();
				app_test_rng_hw();

			} else if (debug_uart_rx == 'e') {

				app_test_aes();

			} else if (debug_uart_rx == 'w') {

				app_test_ecc_sign();

			} else if (debug_uart_rx == 'q') {

				app_test_ecc_compute_public_key();

			} else if (debug_uart_rx == 't') {

				app_test_ecc_shared_secret();

			} else if (debug_uart_rx == 'h') {

				app_test_hash_zero();
				app_test_hash_big();
				app_test_hash_big_two_parts();

			} else if (debug_uart_rx == 's') {

				memset(&res, 0, sizeof(res));
				res.pkt.init.cmd = CTAPHID_PING;
				res.pkt.init.bcnt = lion_htons(1);
				res.pkt.init.payload[0] = 'A';
				bool result = tud_hid_report(0, &res, sizeof(res));
				debug_log("send report result = %d" nl, result);

			}

		}

		if (BspButtonState == BUTTON_PRESSED) {
			BspButtonState = BUTTON_RELEASED;
			BSP_LED_Toggle(LED_GREEN);
		}

		if (ctaphid_has_complete_message_ready(&app_ctaphid)) {

			// Before processing the new message, ensure that the CTAPHID sending queue is completely empty.
			// (i.e., the response to the previous message has been completely sent).
			// Rationale:
			//   While processing the message, the sending does not progress (because tud_task() is only invoked
			//   here in the app_run() while loop and as a part of the ctap_wait_for_user_presence()).
			//   If we received a request (commands) that resulted in a maximum-length long response
			//   while the sending queue had already been partially full, we could not add the response to the queue.
			//
			// Note the CTAPHID layer (ctaphid_process_packet) will correctly reject any new messages
			// with the CTAP1_ERR_CHANNEL_BUSY error code until the message is cleared
			// by calling ctaphid_reset_to_idle() (usually after the message is processed)
			// (see the CTAPHID_RESULT_ERROR case in app_handle_incoming_hid_packet()).
			if (!app_hid_report_send_queue_is_empty()) {
				if (message_wait_time_start == 0) {
					debug_log(yellow("postponing message processing until the ctaphid queue is empty") nl);
					message_wait_time_start = HAL_GetTick();
				}
				continue;
			} else if (message_wait_time_start != 0) {
				debug_log(
					"waited %" PRId32 " ms for the ctaphid queue to be emptied" nl,
					HAL_GetTick() - message_wait_time_start
				);
				message_wait_time_start = 0;
			}

			const ctaphid_channel_buffer_t *message = &app_ctaphid.buffer;
			const uint8_t cmd = message->cmd;

			debug_log(
				nl nl "app_run: " green("ctaphid message ready")
				" cid=0x%08" PRIx32
				" cmd=0x%02" wPRIx8
				" payload_length=%" PRIu16
				nl,
				message->cid, ctaphid_get_cmd_number_per_spec(cmd), message->payload_length
			);

			switch (cmd) {

				case CTAPHID_PING:
					debug_log(cyan("CTAPHID_PING") nl);
					ctaphid_message_to_packets(
						message->cid,
						CTAPHID_PING,
						message->payload_length,
						message->payload,
						handle_packet_using_send_or_queue_ctaphid_packet,
						NULL
					);
					ctaphid_reset_to_idle(&app_ctaphid);
					break;

				case CTAPHID_WINK:
					debug_log(cyan("CTAPHID_WINK") nl);
					if (message->payload_length != 0) {
						info_log(red("error: invalid payload length 0 for CTAPHID_WINK message") nl);
						ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_LENGTH);
						app_hid_report_send_queue_add(&res);
						ctaphid_reset_to_idle(&app_ctaphid);
						break;
					}
					// TODO: Do a LED blinking sequence to provide a "visual identification" of the authenticator.
					ctaphid_create_init_packet(&res, message->cid, CTAPHID_WINK, 0);
					app_hid_report_send_queue_add(&res);
					ctaphid_reset_to_idle(&app_ctaphid);
					break;

				case CTAPHID_CBOR:
					debug_log(cyan("CTAPHID_CBOR") nl);
					if (message->payload_length == 0) {
						info_log(red("error: invalid payload length 0 for CTAPHID_CBOR message") nl);
						ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_LENGTH);
						app_hid_report_send_queue_add(&res);
						ctaphid_reset_to_idle(&app_ctaphid);
						break;
					}
					assert(message->payload_length >= 1);
					app_ctap_reset_keepalive();
					app_ctaphid_cbor_response_buffer[0] = ctap_request(
						&app_ctap,
						message->payload[0],
						message->payload_length - 1,
						&message->payload[1],
						&app_ctap_response
					);
					ctaphid_message_to_packets(
						message->cid,
						CTAPHID_CBOR,
						1 + app_ctap_response.length,
						app_ctaphid_cbor_response_buffer,
						handle_packet_using_send_or_queue_ctaphid_packet,
						NULL
					);
					ctaphid_reset_to_idle(&app_ctaphid);
					break;

				default:
					error_log(
						red("unsupported ctaphid command 0x%02" wPRIx8) nl,
						ctaphid_get_cmd_number_per_spec(cmd)
					);
					ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_COMMAND);
					app_hid_report_send_queue_add(&res);
					ctaphid_reset_to_idle(&app_ctaphid);

			}

		}

	}

}

void app_handle_incoming_hid_packet(const ctaphid_packet_t *packet) {

	debug_log(nl);

	uint8_t error_code;
	ctaphid_process_packet_result_t result = ctaphid_process_packet(
		&app_ctaphid,
		packet,
		&error_code
	);

	ctaphid_packet_t res;
	uint32_t new_channel_id;

	debug_log(
		"app_handle_incoming_hid_packet %s (%d)" nl "  ",
		lion_enum_str(ctaphid_process_packet_result, result),
		result
	);
	dump_hex((const uint8_t *) packet, sizeof(ctaphid_packet_t));

	switch (result) {

		case CTAPHID_RESULT_ERROR:
			ctaphid_create_error_packet(&res, packet->cid, error_code);
			app_hid_report_send_queue_add(&res);
			break;

		case CTAPHID_RESULT_ALLOCATE_CHANNEL:

			new_channel_id = ctaphid_allocate_channel(&app_ctaphid);

			if (new_channel_id == 0) {
				error_log(red(
					"app_handle_incoming_hid_packet: CTAPHID_RESULT_ALLOCATE_CHANNEL error no channel IDs left"
				) nl);
				ctaphid_create_error_packet(&res, packet->cid, error_code);
				app_hid_report_send_queue_add(&res);
				break;
			}

			ctaphid_create_ctaphid_init_response_packet(
				&res,
				packet->pkt.init.payload,
				CTAPHID_BROADCAST_CID,
				app_ctaphid.highest_allocated_cid,
				app_ctaphid_version_major,
				app_ctaphid_version_minor,
				app_ctaphid_version_build,
				app_ctaphid_capabilities
			);
			app_hid_report_send_queue_add(&res);
			break;

		case CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE:
			// Note:
			//   The actual discarding (if there was any) is already finished at this point,
			//   as it is done in the ctaphid_process_packet.
			//   Our only task here is to send the response.
			//   11.2.9.1.3. CTAPHID_INIT (0x06)
			//     https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
			//     ... The device then responds with the CID of the channel it received the INIT on,
			//         using that channel.
			ctaphid_create_ctaphid_init_response_packet(
				&res,
				packet->pkt.init.payload,
				packet->cid,
				app_ctaphid.highest_allocated_cid,
				app_ctaphid_version_major,
				app_ctaphid_version_minor,
				app_ctaphid_version_build,
				app_ctaphid_capabilities
			);
			app_hid_report_send_queue_add(&res);
			break;

		case CTAPHID_RESULT_IGNORED:
			// nothing to do AT ALL
		case CTAPHID_RESULT_BUFFERING:
			// nothing to do AT ALL
		case CTAPHID_RESULT_CANCEL:
			// nothing to do HERE
			//
			// ctaphid_process_packet() sets the cancel flag (ctaphid_state_t.buffer.cancel)
			// on the buffer (which contains a complete CTAPHID_CBOR request).
			// If app_handle_incoming_hid_packet() was invoked during waiting for user presence,
			// the cancellation will be handled once tud_task() returns there.
		case CTAPHID_RESULT_MESSAGE:
			// nothing to do HERE
			//
			// To avoid nested invocations of tud_task() (which is probably not reentrant)
			// and unnecessary deep stack nesting, we leave the handling of this case to app_run.
			//
			// Here is an overview of how it all works together:
			//
			// app_run() {
			//    while(true) {
			//
			//        tud_task() <- TinyUSB device "task"
			//            TinyUSB invokes tud_hid_set_report_cb() if a HID report was received from the host
			//            tud_hid_set_report_cb() invokes app_handle_incoming_hid_packet()
			//                app_handle_incoming_hid_packet()
			//                    processes the HID report by invoking ctaphid_process_packet()
			//                    and immediately handles some of the ctaphid_process_packet_result_t values
			//                    but leaves CTAPHID_RESULT_MESSAGE to app_run
			//
			//        if (ctaphid_has_complete_message_ready(&app_ctaphid)) {
			//            ... CTAPHID_RESULT_MESSAGE is handled here ...
			//            Note that handling CTAPHID_CBOR message (a CTAP request) might involve invoking tud_task()
			//            (and therefore app_handle_incoming_hid_packet()) during waiting for user presence
			//            because we still need to process incoming HID packets and respond to some of them,
			//            even while waiting for the user, resp. processing a CTAP request).
			//        }
			//    }
			// }
			//
			break;

	}

}
