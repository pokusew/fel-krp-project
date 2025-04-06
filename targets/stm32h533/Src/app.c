#include "app.h"
#include "usb.h"
#include "main.h"
#include "utils.h"
#include <stdbool.h>
#include "tusb.h"
#include <stdlib.h>

int ctap_generate_rng(uint8_t *buffer, size_t length) {
	debug_log("ctap_generate_rng: %u bytes to %p" nl, length, buffer);
	for (size_t i = 0; i < length; i++) {
		// TODO: replace stdlib rand() with the STM32H533 RAND peripheral
		buffer[i] = (uint8_t) rand();
	}
	return 1;
}

// supported using UART debug chars:
// l - toggle the Blue LED

// LED status indicators:
// Green  main loop running

ctaphid_state_t app_ctaphid;
ctap_state_t app_ctap;

ctap_user_presence_result_t ctap_wait_for_user_presence(void) {

	debug_log(yellow("waiting for user presence (press the ") cyan("BLUE") yellow(" button) ...") nl);

	const uint32_t timeout_ms = 30 * 1000; // 30 seconds
	uint32_t start_timestamp = HAL_GetTick();

	if (BspButtonState == BUTTON_PRESSED) {
		BspButtonState = BUTTON_RELEASED;
	}

	while (true) {
		tud_task(); // tinyusb device task
		if (app_ctaphid.buffer.cancel) {
			debug_log(yellow("ctap_wait_for_user_presence: ") red("got CANCEL via CTAPHID") nl);
			return CTAP_UP_RESULT_CANCEL;
		}
		uint32_t elapsed_ms = HAL_GetTick() - start_timestamp;
		if (elapsed_ms > timeout_ms) {
			debug_log(yellow("ctap_wait_for_user_presence: ") red("TIMEOUT") nl);
			return CTAP_UP_RESULT_TIMEOUT;
		}
		if (BspButtonState == BUTTON_PRESSED) {
			BspButtonState = BUTTON_RELEASED;
			debug_log(yellow("ctap_wait_for_user_presence: ") green("ALLOW") nl);
			return CTAP_UP_RESULT_ALLOW;
		}
	}

}

noreturn void app_run(void) {

	info_log(nl nl cyan("app_run") nl);

	BSP_LED_On(LED_GREEN);

	uint32_t t1 = HAL_GetTick();

	ctaphid_init(&app_ctaphid);
	ctap_init(&app_ctap);

	uint32_t t2 = HAL_GetTick();

	debug_log("ctap init done in %" PRId32 " ms" nl, t2 - t1);

	usb_init();

	int debug_uart_rx;

	ctaphid_packet_t res;

	// for ctap_request
	uint8_t status;

	while (true) {

		tud_task(); // tinyusb device task

		if ((debug_uart_rx = Debug_UART_Get_Byte()) != -1) {

			debug_log("debug_uart_rx = %c" nl, debug_uart_rx);

			if (debug_uart_rx == 'l') {
				BSP_LED_Toggle(LED_GREEN);
			}

			if (debug_uart_rx == 's') {
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

				case CTAPHID_WINK:
					debug_log(cyan("CTAPHID_WINK") nl);
					if (message->payload_length != 0) {
						info_log(red("error: invalid payload length 0 for CTAPHID_WINK message") nl);
						ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_LENGTH);
						send_or_queue_ctaphid_packet(&res);
						ctaphid_reset_to_idle(&app_ctaphid);
						break;
					}
					ctaphid_create_init_packet(&res, message->cid, CTAPHID_WINK, 0);
					send_or_queue_ctaphid_packet(&res);
					ctaphid_reset_to_idle(&app_ctaphid);
					break;


				case CTAPHID_CBOR:
					debug_log(cyan("CTAPHID_CBOR") nl);
					if (message->payload_length == 0) {
						info_log(red("error: invalid payload length 0 for CTAPHID_CBOR message") nl);
						ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_LENGTH);
						send_or_queue_ctaphid_packet(&res);
						ctaphid_reset_to_idle(&app_ctaphid);
						break;
					}
					assert(message->payload_length >= 1);
					status = ctap_request(
						&app_ctap,
						message->payload[0],
						message->payload_length - 1,
						&message->payload[1]
					);
					ctaphid_cbor_response_to_packets(
						message->cid,
						status,
						app_ctap.response.length,
						app_ctap.response.data,
						send_or_queue_ctaphid_packet
					);
					ctaphid_reset_to_idle(&app_ctaphid);
					break;

				default:
					error_log(
						red("unsupported ctaphid command 0x%02" wPRIx8) nl,
						ctaphid_get_cmd_number_per_spec(cmd)
					);
					ctaphid_create_error_packet(&res, message->cid, CTAP1_ERR_INVALID_LENGTH);
					send_or_queue_ctaphid_packet(&res);
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
		"app_handle_incoming_hid_packet %s (%d)" nl,
		lion_enum_str(ctaphid_process_packet_result, result),
		result
	);
	dump_hex((const uint8_t *) packet, sizeof(ctaphid_packet_t));

	switch (result) {

		case CTAPHID_RESULT_ERROR:
			ctaphid_create_error_packet(&res, packet->cid, error_code);
			send_or_queue_ctaphid_packet(&res);
			break;

		case CTAPHID_RESULT_ALLOCATE_CHANNEL:

			new_channel_id = ctaphid_allocate_channel(&app_ctaphid);

			if (new_channel_id == 0) {
				error_log(red(
					"app_handle_incoming_hid_packet: CTAPHID_RESULT_ALLOCATE_CHANNEL error no channel IDs left"
				) nl);
				ctaphid_create_error_packet(&res, packet->cid, error_code);
				send_or_queue_ctaphid_packet(&res);
				break;
			}

			ctaphid_create_init_response_packet(
				&res,
				packet->pkt.init.payload,
				CTAPHID_BROADCAST_CID,
				app_ctaphid.highest_allocated_cid
			);
			send_or_queue_ctaphid_packet(&res);
			break;

		case CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE:
			// Note:
			//   The actual discarding (if there was any) is already finished at this point,
			//   as it is done in the ctaphid_process_packet.
			//   Our only task here is to send the response.
			ctaphid_create_init_response_packet(
				&res,
				packet->pkt.init.payload,
				CTAPHID_BROADCAST_CID,
				app_ctaphid.highest_allocated_cid
			);
			send_or_queue_ctaphid_packet(&res);
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
			// app_run() {
			//    while(true) {
			//
			//        tud_task() <- TinyUSB device "task"
			//            TinyUSB invokes tud_hid_set_report_cb() if a HID report was received from the host
			//            tud_hid_set_report_cb() invokes app_handle_incoming_hid_packet()
			//                app_handle_incoming_hid_packet()
			//                    processes the HID report by invoking ctaphid_process_packet()
			//                    and immediately handles some of the ctaphid_process_packet_result_t values
			//                    but leave CTAPHID_RESULT_MESSAGE to app_run
			//
			//        if (ctaphid_has_complete_message_ready(&app_ctaphid)) {
			//            ... handle CTAPHID_RESULT_MESSAGE here ...
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
