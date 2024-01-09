/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usbd_custom_hid_if.c
  * @version        : v1.0_Cube
  * @brief          : USB Device Custom HID interface file.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
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
#include "usbd_custom_hid_if.h"

/* USER CODE BEGIN INCLUDE */
#include "utils.h"
#include "fifo.h"
/* USER CODE END INCLUDE */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/

/* USER CODE END PV */

/** @addtogroup STM32_USB_OTG_DEVICE_LIBRARY
  * @brief Usb device.
  * @{
  */

/** @addtogroup USBD_CUSTOM_HID
  * @{
  */

/** @defgroup USBD_CUSTOM_HID_Private_TypesDefinitions USBD_CUSTOM_HID_Private_TypesDefinitions
  * @brief Private types.
  * @{
  */

/* USER CODE BEGIN PRIVATE_TYPES */

/* USER CODE END PRIVATE_TYPES */

/**
  * @}
  */

/** @defgroup USBD_CUSTOM_HID_Private_Defines USBD_CUSTOM_HID_Private_Defines
  * @brief Private defines.
  * @{
  */

/* USER CODE BEGIN PRIVATE_DEFINES */

/* USER CODE END PRIVATE_DEFINES */

/**
  * @}
  */

/** @defgroup USBD_CUSTOM_HID_Private_Macros USBD_CUSTOM_HID_Private_Macros
  * @brief Private macros.
  * @{
  */

/* USER CODE BEGIN PRIVATE_MACRO */

/* USER CODE END PRIVATE_MACRO */

/**
  * @}
  */

/** @defgroup USBD_CUSTOM_HID_Private_Variables USBD_CUSTOM_HID_Private_Variables
  * @brief Private variables.
  * @{
  */

/** Usb HID report descriptor. */
__ALIGN_BEGIN static uint8_t CUSTOM_HID_ReportDesc_FS[USBD_CUSTOM_HID_REPORT_DESC_SIZE] __ALIGN_END = {
	/* USER CODE BEGIN 0 */
	//
	// specification:
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-discovery
	//
	// TODO: During development, change USAGE_PAGE value to allow easy debugging using WebHID.
	//       (FIDO2 HID is on WebHID blocklist for security reasons)
	/* USAGE_PAGE (FIDO Alliance) */ 0x06, 0xd0, 0xf1,
	/* USAGE (Keyboard)           */ 0x09, 0x01,
	/* COLLECTION (Application)   */ 0xa1, 0x01,
	/* USAGE (Input Report Data)  */ 0x09, 0x20,
	/* LOGICAL_MINIMUM (0)        */ 0x15, 0x00,
	/* LOGICAL_MAXIMUM (255)      */ 0x26, 0xff, 0x00,
	/* REPORT_SIZE (8)            */ 0x75, 0x08,
	/* REPORT_COUNT (64)          */ 0x95, 64,
	/* INPUT (Data,Var,Abs)       */ 0x81, 0x02,
	/* USAGE(Output Report Data)  */ 0x09, 0x21,
	/* LOGICAL_MINIMUM (0)        */ 0x15, 0x00,
	/* LOGICAL_MAXIMUM (255)      */ 0x26, 0xff, 0x00,
	/* REPORT_SIZE (8)            */ 0x75, 0x08,
	/* REPORT_COUNT (64)          */ 0x95, 64,
	/* OUTPUT (Data,Var,Abs)      */ 0x91, 0x02,
	//
	/* USER CODE END 0 */
	/* END_COLLECTION	          */ 0xC0
};

/* USER CODE BEGIN PRIVATE_VARIABLES */

/* USER CODE END PRIVATE_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_CUSTOM_HID_Exported_Variables USBD_CUSTOM_HID_Exported_Variables
  * @brief Public variables.
  * @{
  */
extern USBD_HandleTypeDef hUsbDeviceFS;

/* USER CODE BEGIN EXPORTED_VARIABLES */

/* USER CODE END EXPORTED_VARIABLES */
/**
  * @}
  */

/** @defgroup USBD_CUSTOM_HID_Private_FunctionPrototypes USBD_CUSTOM_HID_Private_FunctionPrototypes
  * @brief Private functions declaration.
  * @{
  */

static int8_t CUSTOM_HID_Init_FS(void);

static int8_t CUSTOM_HID_DeInit_FS(void);

static int8_t CUSTOM_HID_OutEvent_FS(uint8_t event_idx, uint8_t state);

/**
  * @}
  */

USBD_CUSTOM_HID_ItfTypeDef USBD_CustomHID_fops_FS = {
	CUSTOM_HID_ReportDesc_FS,
	CUSTOM_HID_Init_FS,
	CUSTOM_HID_DeInit_FS,
	CUSTOM_HID_OutEvent_FS
};

/** @defgroup USBD_CUSTOM_HID_Private_Functions USBD_CUSTOM_HID_Private_Functions
  * @brief Private functions.
  * @{
  */

/* Private functions ---------------------------------------------------------*/

/**
  * @brief  Initializes the CUSTOM HID media low layer
  * @retval USBD_OK if all operations are OK else USBD_FAIL
  */
static int8_t CUSTOM_HID_Init_FS(void) {
	/* USER CODE BEGIN 4 */

	// the print here could mess the logs from the normal context since we are in an interrupt context
	info_log("CUSTOM_HID_Init_FS USB address = %" wPRIu8 nl, hUsbDeviceFS.dev_address);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_SET);

	return (USBD_OK);

	/* USER CODE END 4 */
}

/**
  * @brief  DeInitializes the CUSTOM HID media low layer
  * @retval USBD_OK if all operations are OK else USBD_FAIL
  */
static int8_t CUSTOM_HID_DeInit_FS(void) {
	/* USER CODE BEGIN 5 */

	// Note:
	//   CUSTOM_HID_DeInit_FS is not called immediately when the device is disconnected.
	//   It is only called before a new connection if there was a previous connection.
	// info_log("CUSTOM_HID_DeInit_FS" nl);
	HAL_GPIO_WritePin(LED2_Orange_GPIO_Port, LED2_Orange_Pin, GPIO_PIN_RESET);

	return (USBD_OK);

	/* USER CODE END 5 */
}

/**
  * @brief  Manage the CUSTOM HID class events
  * @param  event_idx: Event index
  * @param  state: Event state
  * @retval USBD_OK if all operations are OK else USBD_FAIL
  */
static int8_t CUSTOM_HID_OutEvent_FS(uint8_t event_idx, uint8_t state) {
	/* USER CODE BEGIN 6 */

	UNUSED(event_idx);
	UNUSED(state);

	USBD_CUSTOM_HID_HandleTypeDef *hhid = (USBD_CUSTOM_HID_HandleTypeDef *) hUsbDeviceFS.pClassDataCmsit[hUsbDeviceFS.classId];

	if (hhid == NULL) {
		return USBD_FAIL;
	}

	// we should avoid printing since we are in an interrupt context, so we could mess the logs from the normal context
	// info_log(cyan("CUSTOM_HID_OutEvent_FS") " counter = %" wPRIu8 nl, hhid->Report_buf[4]);
	RingBuffer_Write(&hidmsg_buffer, hhid->Report_buf, 64);

	// Start next USB packet transfer once data processing is completed
	if (USBD_CUSTOM_HID_ReceivePacket(&hUsbDeviceFS) != (uint8_t) USBD_OK) {
		return -1;
	}

	return (USBD_OK);

	/* USER CODE END 6 */
}

/* USER CODE BEGIN 7 */
/**
  * @brief  Send the report to the Host
  * @param  report: The report to be sent
  * @param  len: The report length
  * @retval USBD_OK if all operations are OK else USBD_FAIL
  */
static uint8_t USBD_CUSTOM_HID_SendReport_FS(uint8_t *report, uint16_t len) {
	return USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, report, len);
}
/* USER CODE END 7 */

/* USER CODE BEGIN PRIVATE_FUNCTIONS_IMPLEMENTATION */

/* USER CODE END PRIVATE_FUNCTIONS_IMPLEMENTATION */
/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

