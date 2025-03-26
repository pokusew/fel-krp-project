#include "app.h"
#include "main.h"
// #include "ctaphid.h"
// #include "ctap.h"
#include "utils.h"
#include <stdbool.h>
#include "tusb.h"

// supported using UART debug chars:
// l - toggle the Blue LED

// LED status indicators:
// Green  main loop running

noreturn void app_run(void) {

	info_log(cyan("app_run") nl);

	BSP_LED_On(LED_GREEN);

	// ctap_init(&app->ctap);
	// ctaphid_init(
	// 	&app->ctaphid,
	// 	(ctaphid_cbor_handler_t) ctap_request,
	// 	&app->ctap
	// );

	int debug_uart_rx;
	uint8_t report[CFG_TUD_ENDPOINT0_SIZE];
	memset(report, 0, sizeof(report));

	while (true) {

		tud_task(); // tinyusb device task

		if ((debug_uart_rx = Debug_UART_Get_Byte()) != -1) {

			info_log("debug_uart_rx = %c" nl, debug_uart_rx);

			if (debug_uart_rx == 'l') {
				BSP_LED_Toggle(LED_GREEN);
			}

			if (debug_uart_rx == 's') {
				report[0] = 'A';
				bool result = tud_hid_report(0, report, sizeof(report));
				info_log("send report result = %d" nl, result);
			}

		}

		if (BspButtonState == BUTTON_PRESSED) {
			BspButtonState = BUTTON_RELEASED;
			BSP_LED_Toggle(LED_GREEN);
		}


	}

}
