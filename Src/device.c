#include "utils.h"
#include "usb_device.h"
#include "usbd_custom_hid_if.h"
#include "device.h"
#include "fifo.h"
#include <inttypes.h>

uint32_t millis() {
	return HAL_GetTick();
}

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

int usbhid_recv(uint8_t *msg) {
	__disable_irq();
	size_t size = RingBuffer_GetDataLength(&hidmsg_buffer);
	assert(size % 64 == 0);
	if (size > 0) {
		// debug_log("%" PRIu32 nl, size);
		size_t read = RingBuffer_Read(&hidmsg_buffer, msg, 64);
		assert(read == 64);
		// printf1(TAG_DUMP2,">> ");
		// dump_hex1(TAG_DUMP2,msg, HID_PACKET_SIZE);
		__enable_irq();
		return 64;
	}
	__enable_irq();
	return 0;
}
