#include <stdbool.h>
// see https://en.cppreference.com/w/c/types/integer
#include <inttypes.h>
#include "ctaphid.h"
#include "ctap.h"


#include "app.h"
#include "utils.h"
#include "usb_device.h"
#include "usbd_custom_hid_if.h"

void app_init(app_state_t *app) {

}

noreturn void app_run(app_state_t *app) {

	// STARTUP

	info_log(cyan("app_run") nl);

	ctaphid_init();
	ctap_init();

	HAL_GPIO_WritePin(LED1_Green_GPIO_Port, LED1_Green_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);

	info_log(cyan("running main loop") nl);

	int debug_uart_rx;

	bool on = true;

	uint8_t report[64] = {0xA1, 0xB2, 0xC3, 0xD4, 0x00};
	uint8_t *const counter = &report[4];
	uint8_t hidmsg[64];

	while (true) {

		// (*counter)++;
		// uint8_t status = USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, report, 64);
		// if (status == USBD_OK) {
		// 	debug_log("sent counter = %" PRIu8 nl, *counter);
		// } else {
		// 	debug_log("sending counter = %"PRIu8 " failed with status = %" PRIu8 nl, *counter, status);
		// }

		// HAL_Delay(5000);

		if ((debug_uart_rx = Debug_UART_Get_Byte()) != -1) {

			if (debug_uart_rx == 'r') {
				if (on) {
					HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_RESET);
					on = false;
				} else {
					HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);
					on = true;
				}
			}

		}

		if (usbhid_recv(hidmsg) > 0)
		{
			ctaphid_handle_packet(hidmsg);
		}
		else
		{
		}
		// ctaphid_check_timeouts();

		// HAL_Delay(1000);

	}

}
