#include "main.h"
#include "tusb.h"
#include "utils.h"

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

	debug_log("usb ready" nl);

}

//--------------------------------------------------------------------+
// Device callbacks
//------------------------------------------------------------

// Invoked when device is mounted
void tud_mount_cb(void) {
	debug_log("tud_mount_cb" nl);
}

// Invoked when device is unmounted
void tud_umount_cb(void) {
	debug_log("tud_umount_cb" nl);
}

// Invoked when usb bus is suspended
// remote_wakeup_en : if host allow us to perform remote wakeup
// Within 7ms, device must draw an average of current less than 2.5 mA from bus
void tud_suspend_cb(bool remote_wakeup_en) {
	debug_log("tud_suspend_cb" nl);
	UNUSED(remote_wakeup_en);
}

// Invoked when usb bus is resumed
void tud_resume_cb(void) {
	debug_log("tud_resume_cb" nl);
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
	debug_log(
		"tud_hid_set_report_cb itf=%" wPRIu8 " report_id=%" wPRIu8 " report_type=%d buffer=%p bufsize=%" PRIu16 nl,
		itf, report_id, report_type, buffer, bufsize
	);
	assert(itf == 0);
	assert(report_id == 0);
	assert(report_type == HID_REPORT_TYPE_OUTPUT);
	// unused because we only have one HID interface and one report
	UNUSED(itf);
	UNUSED(report_id);
	UNUSED(report_type);
	// echo back anything we received from host
	// tud_hid_report(0, buffer, bufsize);
}

// Invoked when sent REPORT successfully to host
// Application can use this to send the next report
// Note: For composite reports, report[0] is report ID
void tud_hid_report_complete_cb(uint8_t instance, const uint8_t *report, uint16_t len) {
	debug_log(
		"tud_hid_report_complete_cb instance=%" wPRIu8 " report=%p len=%" PRIu16 nl,
		instance, report, len
	);
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
	debug_log(
		"tud_hid_report_failed_cb instance=%" wPRIu8 " report_type=%d report=%p xferred_bytes=%" PRIu16 nl,
		instance, report_type, report, xferred_bytes
	);
	UNUSED(instance);
	UNUSED(report_type);
	UNUSED(report);
	UNUSED(xferred_bytes);
}
