#include <stdbool.h>

#include "app.h"
#include "terminal.h"
#include "utils.h"

void app_init(app_state_t *app) {

}

noreturn void app_run(app_state_t *app) {

	// STARTUP

	printf(red("------------------------------") nl);
	printf("starting..." nl);
	debug_sizeof();

	HAL_GPIO_WritePin(LED1_Green_GPIO_Port, LED1_Green_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);

	printf("running..." nl);

	int debug_uart_rx;

	bool on = true;

	while (true) {

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
