#include "utils.h"
#include "usb_device.h"
#include "usbd_custom_hid_if.h"
#include "device.h"
#include "fifo.h"
#include <inttypes.h>

/** Return a millisecond timestamp.  Does not need to be synchronized to anything.
 *  *Optional* to compile, but will not calculate delays correctly without a correct implementation.
*/
uint32_t millis() {
	return HAL_GetTick();
}


/** Called by HIDUSB layer to write bytes to the USB HID interface endpoint.
 *  Will write 64 bytes at a time.
 *
 *  @param msg Pointer to a 64 byte buffer containing a payload to be sent via USB HID.
 *
 *  **Required** to compile and work for FIDO application.
*/
void usbhid_send(uint8_t *msg) {
	while (true) {
		uint8_t status = USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, msg, 64);

		if (status == USBD_OK) {
			debug_log("solo usbhid_send ok" nl);
			return;
		}

		if (status == USBD_BUSY) {
			debug_log("solo usbhid_send busy" nl);
			HAL_Delay(1);
			// TODO: limit max number of repeats
			continue;
		}

		debug_log("solo usbhid_send fail status = %" PRIu8 nl, status);
		exit(1);
	}
}

static uint8_t r = 0;

int ctap_generate_rng(uint8_t *dst, size_t num) {
	// TODO: use STM32's HW generator
	int i;
	for (i = 0; i < num; i++) {
		dst[i] = ++r;
	}
	return 1;
}

int usbhid_recv(uint8_t * msg)
{
	if (fifo_hidmsg_size())
	{
		fifo_hidmsg_take(msg);
		// printf1(TAG_DUMP2,">> ");
		// dump_hex1(TAG_DUMP2,msg, HID_PACKET_SIZE);
		return 64;
	}
	return 0;
}
