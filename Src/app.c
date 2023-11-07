#include <stdbool.h>
// see https://en.cppreference.com/w/c/types/integer
#include <inttypes.h>


#include "app.h"
#include "utils.h"
#include "usb_device.h"
#include "usbd_custom_hid_if.h"

void app_init(app_state_t *app) {

}

noreturn void app_run(app_state_t *app) {

	// STARTUP

	info_log(cyan("app_run") nl);

	HAL_GPIO_WritePin(LED1_Green_GPIO_Port, LED1_Green_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);

	info_log(cyan("running main loop") nl);

	int debug_uart_rx;

	bool on = true;

	uint8_t report[4] = {0xA1, 0xB2, 0xC3, 0xC4};

	while (true) {

		// uint8_t status = USBD_HID_SendReport(&hUsbDeviceFS, report, 4);

		// debug_log("status = %" PRId8 nl, status);

		HAL_Delay(5000);

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

		// HAL_Delay(1000);

	}

}
