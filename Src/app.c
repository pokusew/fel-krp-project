#include "app.h"
#include "ctaphid.h"
#include "ctap.h"
#include "utils.h"
#include "util.h"
#include "log.h"
#include "flash.h"
#include "device.h"
#include "memory_layout.h"
#include "stm32f4xx_ll_tim.h"

// supported using UART debug chars:
// l - toggle the Blue LED
// t - app_test_time
// f - app_flash_info
// c - app_test_ctap_atomic_count
// s - app_test_state_persistence
// d - app_delete_data

// LED status indicators:
// Green  main loop running
// Orange USB status
// Blue   toggle using UART debug char l
// Red    ErrorHandler

static void ensure_flash_initialized();

static void app_test_time();

static void app_flash_info();

static void app_test_ctap_atomic_count();

static void app_test_state_persistence();

static void app_delete_data();

void app_init(app_state_t *app) {
	app->blue_led = true;
}

static void ensure_flash_initialized() {

	info_log(cyan("ensure_flash_initialized") nl);

	uint32_t *magic = (uint32_t *) MAGIC_ADDR;

	if (*magic == MAGIC) {
		info_log(
			green("memory ok (magic 0x%08" PRIx32 " detected at 0x%08" PRIx32 ")") nl,
			(uint32_t) MAGIC, (uint32_t) MAGIC_ADDR
		);
		return;
	}

	info_log(yellow("no magic detected, initializing...") nl);

	app_delete_data();
	const uint32_t correct_magic = MAGIC;
	flash_write(MAGIC_ADDR, (uint8_t *) &correct_magic, sizeof(uint32_t));
	ctap_atomic_count(0);

	if (*magic != MAGIC) {
		error_log(
			red("memory initialized but no magic 0x%08" PRIx32 " detected at 0x%08" PRIx32) nl,
			(uint32_t) MAGIC, (uint32_t) MAGIC_ADDR
		);
		Error_Handler();
	}

	info_log(
		green("memory initialized and magic 0x%08" PRIx32 " verified at 0x%08" PRIx32) nl,
		(uint32_t) MAGIC, (uint32_t) MAGIC_ADDR
	);

}

static void app_test_time() {

	info_log(cyan("app_test_time") nl);

	info_log(
		"millis = %" PRIu32 ", HAL_GetTick = %" PRIu32 ", TIM2 = %" PRIu32 nl,
		millis(), HAL_GetTick(), LL_TIM_GetCounter(TIM2) / 1000
	);
	HAL_Delay(1000);
	// while the flash is being erased, uwTick (HAL_GetTick) is not updated correctly
	// flash_erase_sector(STATE_SECTOR);
	info_log(
		"millis = %" PRIu32 ", HAL_GetTick = %" PRIu32 ", TIM2 = %" PRIu32 nl,
		millis(), HAL_GetTick(), LL_TIM_GetCounter(TIM2) / 1000
	);

}

static void app_flash_info() {

	info_log(cyan("app_flash_info") nl);

	timestamp();

	uint32_t counter_num_erases_sector = flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR);
	uint32_t counter_data_sector = flash_128KB_sector_to_addr(COUNTER_DATA_SECTOR);
	uint32_t state_sector = flash_128KB_sector_to_addr(STATE_SECTOR);
	uint32_t state_backup_sector = flash_128KB_sector_to_addr(STATE_BACKUP_SECTOR);

	info_log("counter_num_erases_sector = 0x%08" PRIx32 nl, counter_num_erases_sector);
	info_log("counter_data_sector       = 0x%08" PRIx32 nl, counter_data_sector);
	info_log("state_sector              = 0x%08" PRIx32 nl, state_sector);
	info_log("state_backup_sector       = 0x%08" PRIx32 nl, state_backup_sector);

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

static void app_test_ctap_atomic_count() {

	info_log(cyan("app_test_ctap_atomic_count") nl);

	timestamp();

	uint32_t counter = ctap_atomic_count(0);

	info_log("counter = %" PRIu32 nl, counter);

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

static void app_test_state_persistence() {

	info_log(cyan("app_test_state_persistence") nl);

	timestamp();

	authenticator_write_state(&STATE);

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

static void app_delete_data() {

	info_log(cyan("app_delete_data") nl);

	timestamp();

	flash_erase_sector(STATE_SECTOR);
	// flash_erase_sector(STATE_BACKUP_SECTOR);
	flash_erase_sector(COUNTER_NUM_ERASES_SECTOR);
	flash_erase_sector(COUNTER_DATA_SECTOR);

	info_log("done in %" PRIu32 " ms" nl, timestamp());

}

noreturn void app_run(app_state_t *app) {

	info_log(cyan("app_run") nl);

	ensure_flash_initialized();

	ctaphid_init();
	ctap_init();

	if (app->blue_led) {
		HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_RESET);
		app->blue_led = false;
	} else {
		HAL_GPIO_WritePin(LED4_Blue_GPIO_Port, LED4_Blue_Pin, GPIO_PIN_SET);
		app->blue_led = true;
	}

	info_log(cyan("running main loop") nl);

	HAL_GPIO_WritePin(LED1_Green_GPIO_Port, LED1_Green_Pin, GPIO_PIN_SET);

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
				app_flash_info();
			}

			if (debug_uart_rx == 'c') {
				app_test_ctap_atomic_count();
			}

			if (debug_uart_rx == 't') {
				app_test_time();
			}

			if (debug_uart_rx == 's') {
				app_test_state_persistence();
			}

			if (debug_uart_rx == 'd') {
				app_delete_data();
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
