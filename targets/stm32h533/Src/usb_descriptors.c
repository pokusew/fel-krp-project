#include "tusb.h"
#include "stm32h533xx.h"
#include "stm32h5xx_ll_utils.h"
#include <assert.h>

//--------------------------------------------------------------------+
// Device Descriptor
//--------------------------------------------------------------------+

static const tusb_desc_device_t device_descriptor = {
	.bLength            = sizeof(tusb_desc_device_t),
	.bDescriptorType    = TUSB_DESC_DEVICE,
	.bcdUSB             = 0x0200,
	.bDeviceClass       = 0x00,
	.bDeviceSubClass    = 0x00,
	.bDeviceProtocol    = 0x00,
	.bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

	.idVendor = 0x1209,
	.idProduct = 0x0001,
	.bcdDevice = 0x0100,

	.iManufacturer = 0x01,
	.iProduct = 0x02,
	.iSerialNumber = 0x03,

	.bNumConfigurations = 0x01
};

// Invoked when received GET DEVICE DESCRIPTOR request
// Application returns a pointer to the device descriptor
const uint8_t *tud_descriptor_device_cb(void) {
	return (const uint8_t *) &device_descriptor;
}

//--------------------------------------------------------------------+
// HID Report Descriptor
//--------------------------------------------------------------------+

static const uint8_t hid_report_descriptor[] = {
	TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)
};

// Invoked when received GET HID REPORT DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
const uint8_t *tud_hid_descriptor_report_cb(uint8_t itf) {
	(void) itf; // unused, only useful if we had multiple HID interfaces
	return hid_report_descriptor;
}

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

enum endpoint_number {
	HID_INTERFACE_NUMBER,
	ITF_NUM_TOTAL
};
#define CONFIGURATION_DESCRIPTOR_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
#define ENDPOINT_NUM_HID   0x01

static const uint8_t configuration_descriptor[] = {
	TUD_CONFIG_DESCRIPTOR(
		1,               // the configuration number (index)
		ITF_NUM_TOTAL,   // number of interfaces in the configuration
		0,               // index of a string descriptor describing the configuration
		CONFIGURATION_DESCRIPTOR_TOTAL_LEN, // total length (size of this config description + all interfaces descriptors)
		0x00,            // attribute
		100              // power in mA
	),
	TUD_HID_INOUT_DESCRIPTOR(
		HID_INTERFACE_NUMBER,   // Interface number
		0,                      // index of a string descriptor describing the interface
		HID_ITF_PROTOCOL_NONE,  // protocol
		sizeof(hid_report_descriptor), // report descriptor len
		ENDPOINT_NUM_HID,              // Endpoint Address (OUT)
		0x80 | ENDPOINT_NUM_HID,       // Endpoint Address (IN)
		CFG_TUD_HID_EP_BUFSIZE, // endpoints max packet size
		5                       // endpoints polling interval
	)
};

TU_VERIFY_STATIC(
	sizeof(configuration_descriptor) == CONFIGURATION_DESCRIPTOR_TOTAL_LEN,
	"invalid CONFIGURATION_DESCRIPTOR_TOTAL_LEN"
);

// Invoked when received GET CONFIGURATION DESCRIPTOR request
// Application returns pointer to a configuration descriptor (corresponding to the given index)
// The contents of the returned pointer must exist long enough for transfer to complete.
const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
	(void) index; // unused, only useful for multiple configurations
	return configuration_descriptor;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

enum string_descriptor_index {
	STRID_LANGID = 0,
	STRID_MANUFACTURER,
	STRID_PRODUCT,
	STRID_SERIAL,
	STRID_NUM_TOTAL,
};

// array of pointer to string descriptors
static const char *string_desc_arr[] = {
	(const char[]) {0x09, 0x04}, // 0: is supported language is English (0x0409)
	"Martin Endler",            // 1: Manufacturer
	"LionKey",                  // 2: Product
	NULL,                       // 3: Serials will use unique ID if possible
};

static_assert(
	sizeof(string_desc_arr) / sizeof(string_desc_arr[0]) == STRID_NUM_TOTAL,
	"invalid STRID_NUM_TOTAL, fix string_desc_arr"
);


//  1x uint16_t (2 bytes) for the string descriptor header
//    (first byte is length (including header), second byte is string type)
// 32x uint16_t (64 bytes) for 32 UTF-16 characters
#define STRING_DESCRIPTOR_MAX_NUM_CHARS 32
static uint16_t string_descriptor_buffer[1 + STRING_DESCRIPTOR_MAX_NUM_CHARS];

static size_t board_get_unique_id(uint8_t id[], size_t max_len) {
	(void) max_len;
	const size_t len = 12;
	assert(max_len >= len);

	uint32_t *id32 = (uint32_t *) id;

	volatile uint32_t *stm32_uuid = (volatile uint32_t *) UID_BASE;
	id32[0] = stm32_uuid[0];
	id32[1] = stm32_uuid[1];
	id32[2] = stm32_uuid[2];

	// alternative we could use the functions from UTILS LL module (stm32h5xx_ll_utils.h)
	// id32[0] = LL_GetUID_Word0();
	// id32[1] = LL_GetUID_Word1();
	// id32[2] = LL_GetUID_Word2();

	return len;
}

// Get USB Serial number string from unique ID if available. Return number of character.
// Input is string descriptor from index 1 (index 0 is type + len)
static size_t board_usb_get_serial(uint16_t desc_str1[], size_t max_chars) {

	uint8_t uid[12] TU_ATTR_ALIGNED(4);

	size_t uid_len = board_get_unique_id(uid, sizeof(uid));

	if (uid_len > max_chars / 2) {
		uid_len = max_chars / 2;
	}

	for (size_t i = 0; i < uid_len; i++) {
		for (size_t j = 0; j < 2; j++) {
			const char nibble_to_hex[16] = {
				'0', '1', '2', '3', '4', '5', '6', '7',
				'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
			};
			const uint8_t nibble = (uid[i] >> (j * 4)) & 0xf;
			desc_str1[i * 2 + (1 - j)] = nibble_to_hex[nibble]; // UTF-16-LE
		}
	}

	return 2 * uid_len;
}

// Invoked when received GET STRING DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
	(void) langid; // unused, only useful if we supported multiple languages

	uint16_t *const string_descriptor_buffer_chars = &string_descriptor_buffer[1];
	size_t num_chars;

	switch (index) {
		case STRID_LANGID:
			memcpy(string_descriptor_buffer_chars, string_desc_arr[0], 2);
			num_chars = 1;
			break;

		case STRID_SERIAL:
			num_chars = board_usb_get_serial(
				string_descriptor_buffer_chars,
				STRING_DESCRIPTOR_MAX_NUM_CHARS
			);
			break;

		default:
			// Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
			// https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

			// unknown string index (out of bounds)
			if (index >= 4) {
				return NULL;
			}

			const char *str = string_desc_arr[index];

			num_chars = strlen(str);
			if (num_chars > STRING_DESCRIPTOR_MAX_NUM_CHARS) {
				num_chars = STRING_DESCRIPTOR_MAX_NUM_CHARS;
			}

			// Convert ASCII string into UTF-16
			for (size_t i = 0; i < num_chars; i++) {
				string_descriptor_buffer[1 + i] = str[i];
			}
			break;
	}

	assert(num_chars > 0);

	// first byte is length (including header), second byte is string type
	string_descriptor_buffer[0] = (uint16_t) ((TUSB_DESC_STRING << 8) | (2 * num_chars + 2));

	return string_descriptor_buffer;
}
