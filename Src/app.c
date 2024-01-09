#include "app.h"
#include "ctaphid.h"
#include "ctap.h"
#include "utils.h"
#include "util.h"
#include "log.h"
#include "flash.h"
#include "device.h"
#include "memory_layout.h"


void app_init(app_state_t *app) {
	app->blue_led = true;
}

// LED status indicators:
// Green  (unused)
// Orange (unused)
// Blue   toggle using UART debug char l
// Red    ErrorHandler

static void app_test_flash() {

	info_log(cyan("app_test_flash") nl);

	timestamp();

	uint32_t counter_num_erases_sector = flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR);
	uint32_t counter_data_sector = flash_128KB_sector_to_addr(COUNTER_DATA_SECTOR);
	uint32_t state_1_sector = flash_128KB_sector_to_addr(STATE1_SECTOR);
	uint32_t state_2_sector = flash_128KB_sector_to_addr(STATE2_SECTOR);

	info_log("counter_num_erases_sector = 0x%08" PRIx32 nl, counter_num_erases_sector);
	info_log("counter_data_sector       = 0x%08" PRIx32 nl, counter_data_sector);
	info_log("state_1_sector            = 0x%08" PRIx32 nl, state_1_sector);
	info_log("state_2_sector            = 0x%08" PRIx32 nl, state_2_sector);

	// TODO

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

static void app_test_ctap_atomic_count() {
	info_log(cyan("app_test_ctap_atomic_count") nl);

	timestamp();

	ctap_atomic_count(0);

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

noreturn void app_run(app_state_t *app) {

	info_log(cyan("app_run") nl);

	ctaphid_init();
	ctap_init();

	HAL_GPIO_WritePin(LED1_Green_GPIO_Port, LED1_Green_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_SET);
	HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);

	info_log(cyan("running main loop") nl);

	int debug_uart_rx;
	uint8_t hidmsg[64];

	while (true) {

		if ((debug_uart_rx = Debug_UART_Get_Byte()) != -1) {

			if (debug_uart_rx == 'l') {
				if (app->blue_led) {
					HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_RESET);
					app->blue_led = false;
				} else {
					HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);
					app->blue_led = true;
				}
			}

			if (debug_uart_rx == 'f') {
				app_test_flash();
			}

			if (debug_uart_rx == 'c') {
				app_test_ctap_atomic_count();
			}

		}

		if (usbhid_recv(hidmsg) > 0) {

			// TODO: remove after debugging
			dump_hex(hidmsg, 64);

			ctaphid_handle_packet(hidmsg);

		}

		// TODO
		// ctaphid_check_timeouts();

	}

}
