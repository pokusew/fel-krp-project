/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "tusb.h"
#include "utils.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

COM_InitTypeDef BspCOMInit;
__IO uint32_t BspButtonState = BUTTON_RELEASED;

PCD_HandleTypeDef hpcd_USB_DRD_FS;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);

static void MX_GPIO_Init(void);

static void MX_USB_PCD_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void) {

	/* USER CODE BEGIN 1 */

	/* USER CODE END 1 */

	/* MCU Configuration--------------------------------------------------------*/

	/* Reset of all peripherals, Initializes the Flash interface and the Systick. */
	HAL_Init();

	/* USER CODE BEGIN Init */

	/* USER CODE END Init */

	/* Configure the system clock */
	SystemClock_Config();

	/* USER CODE BEGIN SysInit */

	/* USER CODE END SysInit */

	/* Initialize all configured peripherals */
	MX_GPIO_Init();
	MX_USB_PCD_Init();
	/* USER CODE BEGIN 2 */

	/* USER CODE END 2 */

	/* Initialize leds */
	BSP_LED_Init(LED_GREEN);

	/* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
	BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

	/* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
	BspCOMInit.BaudRate = 115200;
	BspCOMInit.WordLength = COM_WORDLENGTH_8B;
	BspCOMInit.StopBits = COM_STOPBITS_1;
	BspCOMInit.Parity = COM_PARITY_NONE;
	BspCOMInit.HwFlowCtl = COM_HWCONTROL_NONE;
	if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE) {
		Error_Handler();
	}

	/* USER CODE BEGIN BSP */

	// init device stack on the configured roothub port
	tusb_rhport_init_t dev_init = {
		.role = TUSB_ROLE_DEVICE,
		.speed = TUSB_SPEED_AUTO
	};
	tusb_rhport_init(0, &dev_init);

	/* -- Sample board code to send message over COM1 port ---- */
	printf("Welcome to STM32 world !\n\r");

	/* -- Sample board code to switch on leds ---- */
	BSP_LED_On(LED_GREEN);

	/* USER CODE END BSP */

	/* Infinite loop */
	/* USER CODE BEGIN WHILE */
	while (1) {

		tud_task(); // tinyusb device task

		/* -- Sample board code for User push-button in interrupt mode ---- */
		if (BspButtonState == BUTTON_PRESSED) {
			/* Update button state */
			BspButtonState = BUTTON_RELEASED;
			/* -- Sample board code to toggle leds ---- */
			BSP_LED_Toggle(LED_GREEN);
			/* ..... Perform your action ..... */
		}

		/* USER CODE END WHILE */

		/* USER CODE BEGIN 3 */
	}
	/* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void) {
	RCC_OscInitTypeDef RCC_OscInitStruct = {0};
	RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

	/** Configure the main internal regulator output voltage
	*/
	__HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE3);

	while (!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}

	/** Initializes the RCC Oscillators according to the specified parameters
	* in the RCC_OscInitTypeDef structure.
	*/
	RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
	RCC_OscInitStruct.HSEState = RCC_HSE_ON;
	RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
	RCC_OscInitStruct.PLL.PLLSource = RCC_PLL1_SOURCE_HSE;
	RCC_OscInitStruct.PLL.PLLM = 2;
	RCC_OscInitStruct.PLL.PLLN = 16;
	RCC_OscInitStruct.PLL.PLLP = 6;
	RCC_OscInitStruct.PLL.PLLQ = 4;
	RCC_OscInitStruct.PLL.PLLR = 2;
	RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1_VCIRANGE_3;
	RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1_VCORANGE_WIDE;
	RCC_OscInitStruct.PLL.PLLFRACN = 0;
	if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
		Error_Handler();
	}

	/** Initializes the CPU, AHB and APB buses clocks
	*/
	RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
								  | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2
								  | RCC_CLOCKTYPE_PCLK3;
	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;

	if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK) {
		Error_Handler();
	}

	/** Configure the programming delay
	*/
	__HAL_FLASH_SET_PROGRAM_DELAY(FLASH_PROGRAMMING_DELAY_0);
}

/**
  * @brief USB Initialization Function
  * @param None
  * @retval None
  */
static void MX_USB_PCD_Init(void) {

	/* USER CODE BEGIN USB_Init 0 */

	/* USER CODE END USB_Init 0 */

	/* USER CODE BEGIN USB_Init 1 */

	/* USER CODE END USB_Init 1 */
	hpcd_USB_DRD_FS.Instance = USB_DRD_FS;
	hpcd_USB_DRD_FS.Init.dev_endpoints = 8;
	hpcd_USB_DRD_FS.Init.speed = USBD_FS_SPEED;
	hpcd_USB_DRD_FS.Init.phy_itface = PCD_PHY_EMBEDDED;
	hpcd_USB_DRD_FS.Init.Sof_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.low_power_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.lpm_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.battery_charging_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.vbus_sensing_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.bulk_doublebuffer_enable = DISABLE;
	hpcd_USB_DRD_FS.Init.iso_singlebuffer_enable = DISABLE;
	if (HAL_PCD_Init(&hpcd_USB_DRD_FS) != HAL_OK) {
		Error_Handler();
	}
	/* USER CODE BEGIN USB_Init 2 */

	/* USER CODE END USB_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void) {
	GPIO_InitTypeDef GPIO_InitStruct = {0};
	/* USER CODE BEGIN MX_GPIO_Init_1 */

	/* USER CODE END MX_GPIO_Init_1 */

	/* GPIO Ports Clock Enable */
	__HAL_RCC_GPIOC_CLK_ENABLE();
	__HAL_RCC_GPIOH_CLK_ENABLE();
	__HAL_RCC_GPIOA_CLK_ENABLE();
	__HAL_RCC_GPIOB_CLK_ENABLE();

	/*Configure GPIO pin : PC4 */
	GPIO_InitStruct.Pin = GPIO_PIN_4;
	GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
	GPIO_InitStruct.Pull = GPIO_NOPULL;
	HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

	/* USER CODE BEGIN MX_GPIO_Init_2 */

	/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

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
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void tud_hid_set_report_cb(
	uint8_t itf,
	uint8_t report_id,
	hid_report_type_t report_type,
	uint8_t const *buffer,
	uint16_t bufsize
) {
	debug_log(
		"tud_hid_set_report_cb itf=%" wPRIu8 " report_id=%" wPRIu8 " report_type=%d bufsize=%" PRIu16 nl,
		itf, report_id, report_type, bufsize
	);
	// unused because we only have one HID interface and one report
	UNUSED(itf);
	UNUSED(report_id);
	UNUSED(report_type);
	// echo back anything we received from host
	tud_hid_report(0, buffer, bufsize);
}

/* USER CODE END 4 */

/**
  * @brief  BSP Push Button callback
  * @param  Button Specifies the pressed button
  * @retval None
  */
void BSP_PB_Callback(Button_TypeDef Button) {
	if (Button == BUTTON_USER) {
		BspButtonState = BUTTON_PRESSED;
	}
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void) {
	/* USER CODE BEGIN Error_Handler_Debug */
	/* User can add his own implementation to report the HAL error return state */
	__disable_irq();
	while (1) {
	}
	/* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
	 ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
