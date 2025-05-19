#include "main.h"
#include "app.h"
#include "tusb.h"
#include "utils.h"

static_assert(sizeof(ctaphid_packet_t) == CFG_TUD_ENDPOINT0_SIZE, "invalid sizeof(ctaphid_packet_t)");
// Caution!
//   TU_FIFO_DEF macro does not use parentheses around arguments, so we must explicitly wrap
//   any expressions such as `CTAPHID_MESSAGE_MAX_NUM_PACKETS + 1` ourselves,
//   otherwise it would result in a critical fault.
TU_FIFO_DEF(app_hid_report_send_queue, (CTAPHID_MESSAGE_MAX_NUM_PACKETS), ctaphid_packet_t, false);

void app_hid_task(void) {
	tud_task(); // tinyusb device task
	app_hid_report_send_queue_send_one_if_possible();
}

void app_hid_report_send_queue_add(const ctaphid_packet_t *packet, bool fail_if_full) {

#if LIONKEY_DEBUG_LEVEL > 0
	// do not log keepalive messages at all
	if (packet->pkt.init.cmd != CTAPHID_KEEPALIVE) {
		debug_log("app_hid_report_send_queue_add" nl);
	}
#endif

	if (!tu_fifo_write(&app_hid_report_send_queue, packet)) {
		error_log(red("app_hid_report_send_queue_add: fatal error: tu_fifo_write failed, the queue is full") nl);
		if (fail_if_full) {
			Error_Handler();
		}
	}

}

void app_hid_report_send_queue_send_one_if_possible(void) {

	if (tu_fifo_empty(&app_hid_report_send_queue)) {
		return;
	}

	ctaphid_packet_t packet;

	if (!tu_fifo_peek(&app_hid_report_send_queue, &packet)) {
		error_log(red("app_hid_report_send_queue_send_one_if_possible: error tu_fifo_peek") nl);
		return;
	}

	if (tud_hid_report(0, &packet, sizeof(ctaphid_packet_t))) {
		// debug_log("app_hid_report_send_queue_send_one_if_possible: sent" nl);
		tu_fifo_advance_read_pointer(&app_hid_report_send_queue, 1);
	} else {
		// debug_log(red("app_hid_report_send_queue_send_one_if_possible: could not send") nl);
	}

}

bool app_hid_report_send_queue_is_empty(void) {
	return tu_fifo_empty(&app_hid_report_send_queue);
}

void usb_init(void) {

	debug_log("initializing usb ..." nl);

	// Configure USB peripheral manually (TinyUSB does not use the HAL PCD layer)
	// PCD = USB peripheral controller driver
	// Note: We perform the configuration in the same order as in the CubeMX-generated HAL_PCD_MspInit.
	// 1. Configure USB clock (but does not yet enable it).
	RCC_PeriphCLKInitTypeDef USB_ClkInitStruct = {0};
	USB_ClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_USB;
	USB_ClkInitStruct.UsbClockSelection = RCC_USBCLKSOURCE_PLL1Q;
	if (HAL_RCCEx_PeriphCLKConfig(&USB_ClkInitStruct) != HAL_OK) {
		Error_Handler();
	}
	// 2. Enable VDDUSB.
	HAL_PWREx_EnableVddUSB();
	// 3. Enable USB peripheral clock.
	__HAL_RCC_USB_CLK_ENABLE();

	// Continue with the TinyUSB configration...
	// init device stack on the configured roothub port
	// (STM32H533RET6 only has one "roothub port", i.e., the USB 2.0 Full-Speed peripheral)
	tusb_rhport_init_t dev_init = {
		.role = TUSB_ROLE_DEVICE,
		.speed = TUSB_SPEED_AUTO
	};
	tusb_rhport_init(0, &dev_init);

	info_log("usb initialized" nl);

}

//--------------------------------------------------------------------+
// Device callbacks
//------------------------------------------------------------

// Expected USB-status related callback order (as currently observed):
// a) When powered on (power via ST-LINK)
//    while USB cable disconnected, then later USB connected to the host:
//    1. usb initialized
//    2. (USB connected to the host)
//    3. usb device mounted (tud_mount_cb)
// b) When powered on (power via ST-LINK)
//    while USB cable is connected to the host:
//    1. usb initialized
//    2. usb device mounted (tud_mount_cb)
// c) When USB cable is disconnected during runtime and later reconnected again:
//    1. usb initialized
//    2. (USB connected to the host)
//    3. usb device mounted (tud_mount_cb)
//    4. (USB cable is disconnected)
//    5. usb bus is suspended (tud_suspend_cb)
//    6. (USB connected to the host)
//    7. usb bus is resumed (tud_resume_cb)
//    8. usb device mounted (tud_mount_cb)
//    Note: Currently, it seems that tud_umount_cb is never invoked.

// Invoked when device is mounted
void tud_mount_cb(void) {
	info_log(green("usb device mounted") nl);
	// Note:
	//   This is a development-only workaround to simulate the "reboot" (MCU reset) behavior
	//   even without the actual reset.
	// Rationale:
	//   During debugging, when LionKey is powered from ST-LINK, it is possible
	//   to connect/disconnect/reconnect the USB (USER USB port) and the MCU preserves its state (including RAM).
	//   During normal operation (no ST-LINK connected), LionKey is powered directly from the USB bus (USER USB port).
	//   Therefore, disconnecting USB powers down LionKey and the MCU state (RAM) is lost.
	//   Once reconnected, the standard power-on reset sequence runs (during which the pin_boot_remaining_attempts
	//   is set to its per-boot value).
#if LIONKEY_DEVELOPMENT_OVERRIDE == 1
	app_ctap.init_time = ctap_get_current_time();
	app_ctap.pin_boot_remaining_attempts = CTAP_PIN_PER_BOOT_ATTEMPTS;
#endif
}

// Invoked when device is unmounted
void tud_umount_cb(void) {
	info_log(yellow("usb device unmounted") nl);
}

// Invoked when usb bus is suspended
// remote_wakeup_en : if host allow us to perform remote wakeup
// Within 7ms, device must draw an average of current less than 2.5 mA from bus
void tud_suspend_cb(bool remote_wakeup_en) {
	info_log(yellow("usb bus is suspended") nl);
	UNUSED(remote_wakeup_en);
}

// Invoked when usb bus is resumed
void tud_resume_cb(void) {
	info_log("usb bus is resumed" nl);
}

//--------------------------------------------------------------------+
// USB HID
//--------------------------------------------------------------------+

// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request
uint16_t tud_hid_get_report_cb(
	uint8_t itf,
	uint8_t report_id,
	hid_report_type_t report_type,
	uint8_t *buffer,
	uint16_t reqlen
) {
	debug_log(
		"tud_hid_get_report_cb itf=%" wPRIu8 " report_id=%" wPRIu8 " report_type=%d reqlen=%" PRIu16 nl,
		itf, report_id, report_type, reqlen
	);
	UNUSED(itf);
	UNUSED(report_id);
	UNUSED(report_type);
	UNUSED(buffer);
	UNUSED(reqlen);
	return 0;
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint (Report ID = 0, Type = OUTPUT)
void tud_hid_set_report_cb(
	uint8_t itf,
	uint8_t report_id,
	hid_report_type_t report_type,
	const uint8_t *buffer,
	uint16_t bufsize
) {

	// debug_log(
	// 	"tud_hid_set_report_cb: itf=%" wPRIu8 " report_id=%" wPRIu8 " report_type=%d buffer=%p bufsize=%" PRIu16 nl,
	// 	itf, report_id, report_type, buffer, bufsize
	// );

	assert(itf == 0);
	assert(report_id == 0);
	assert(report_type == HID_REPORT_TYPE_OUTPUT);

	// unused because we only have one HID interface and one report
	UNUSED(itf);
	UNUSED(report_id);
	UNUSED(report_type);

	// check that the bufsize is the expected HID report size
	static_assert(sizeof(ctaphid_packet_t) == CFG_TUD_ENDPOINT0_SIZE, "invalid sizeof(ctaphid_packet_t)");
	if (bufsize != sizeof(ctaphid_packet_t)) {
		error_log(
			red("tud_hid_set_report_cb: unexpected bufsize (got %" PRIu16 " bytes but expected %u bytes)")
			" ignoring this report" nl "  ",
			bufsize, sizeof(ctaphid_packet_t)
		);
		dump_hex(buffer, bufsize);
		return;
	}

	const ctaphid_packet_t *packet = (const ctaphid_packet_t *) buffer;
	app_handle_incoming_hid_packet(packet);

}

// Invoked when sent REPORT successfully to host
// Application can use this to send the next report
// Note: For composite reports, report[0] is report ID
void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report, uint16_t len) {

#if LIONKEY_DEBUG_LEVEL > 0
	// do not log keepalive messages at all
	if (len == CTAPHID_PACKET_SIZE && report[4] == CTAPHID_KEEPALIVE) {
		return;
	}
	debug_log(
		"tud_hid_report_complete_cb instance=%" wPRIu8 " report=%p len=%" PRIu16 nl "  ",
		instance, report, len
	);
	dump_hex(report, len);
#endif

	UNUSED(instance);
	UNUSED(report);
	UNUSED(len);

}

// Invoked when a transfer wasn't successful
void tud_hid_report_failed_cb(
	uint8_t instance,
	hid_report_type_t report_type,
	const uint8_t *report,
	uint16_t xferred_bytes
) {

	error_log(
		red("tud_hid_report_failed_cb instance=%" wPRIu8 " report_type=%d report=%p xferred_bytes=%" PRIu16) nl,
		instance, report_type, report, xferred_bytes
	);

	UNUSED(instance);
	UNUSED(report_type);
	UNUSED(report);
	UNUSED(xferred_bytes);

	if (report_type == HID_REPORT_TYPE_OUTPUT) {
		// TODO: repeat N times before fatal error
		error_log(red("fatal error tud_hid_report_failed_cb OUT") nl);
		Error_Handler();
	}

}
