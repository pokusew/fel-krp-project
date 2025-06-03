#include "app.h"
#include "app_test.h"
#include "main.h"
#include "tusb.h"

// supported using UART debug chars:
// l - toggle the Blue LED

// LED status indicators:
// Green  main loop running

static Status_LED_Mode test_current_led_mode = STATUS_LED_MODE_OFF;

void app_debug_task(void) {

	int debug_uart_rx = Debug_UART_Get_Byte();

	// no UART data received
	if (debug_uart_rx == -1) {
		return;
	}

	debug_log("debug_uart_rx = %c" nl, debug_uart_rx);

	if (debug_uart_rx == 'l') {
		if (test_current_led_mode == STATUS_LED_MODE_BLINKING_SPECIAL) {
			test_current_led_mode = STATUS_LED_MODE_OFF;
		} else {
			test_current_led_mode++;
		}
		Status_LED_Set_Mode(test_current_led_mode);
		return;
	}

	if (debug_uart_rx == 'f') {
		app_test_flash();
		return;
	}

	if (debug_uart_rx == 'd') {
		app_test_flash_high_cycling();
		return;
	}

	if (debug_uart_rx == 'c') {
		app_test_signature_counter();
		return;
	}

	if (debug_uart_rx == 'r') {
		app_test_rng_tinymt();
		app_test_rng_hw();
		return;
	}

	if (debug_uart_rx == 'e') {
		app_test_aes();
		return;
	}

	if (debug_uart_rx == 'w') {
		app_test_ecc_sign();
		return;
	}

	if (debug_uart_rx == 'q') {
		app_test_ecc_compute_public_key();
		return;
	}

	if (debug_uart_rx == 't') {
		app_test_ecc_shared_secret();
		return;
	}

	if (debug_uart_rx == 'h') {
		app_test_hash_zero();
		app_test_hash_big();
		app_test_hash_big_two_parts();
		return;
	}

	if (debug_uart_rx == 'b') {
		// for testing: simulate the "reboot" (MCU reset) behavior without the actual reset
		app_ctap.init_time = ctap_get_current_time();
		app_ctap.pin_boot_remaining_attempts = CTAP_PIN_PER_BOOT_ATTEMPTS;
		info_log("power cycle simulated" nl);
		return;
	}

	if (debug_uart_rx == 'u') {
		BspButtonState = BUTTON_PRESSED;
		info_log("user presence simulated" nl);
		return;
	}

	if (debug_uart_rx == 'p') {
		info_log("pin_total_remaining_attempts = %" wPRIu8 nl, app_ctap.pin_state.pin_total_remaining_attempts);
		info_log("pin_boot_remaining_attempts = %" wPRIu8 nl, app_ctap.pin_boot_remaining_attempts);
		return;
	}

	if (debug_uart_rx == 's') {
		ctaphid_packet_t packet;
		memset(&packet, 0, sizeof(packet));
		packet.pkt.init.cmd = CTAPHID_PING;
		packet.pkt.init.bcnt = lion_htons(1);
		packet.pkt.init.payload[0] = 'A';
		bool result = tud_hid_report(0, &packet, sizeof(packet));
		debug_log("tud_hid_report result = %d" nl, result);
		return;
	}

	// ignore unknown debug_uart_rx commands (a command is a single character)

}

void app_test_flash(void) {
	info_log(cyan("app_test_flash") nl);

	HAL_StatusTypeDef status;

	// FLASH_TYPEPROGRAM_QUADWORD
	// FLASH_TYPEPROGRAM_HALFWORD_EDATA
	// FLASH_TYPEPROGRAM_WORD_EDATA

	uint32_t flash_address = FLASH_BASE + FLASH_BANK_SIZE;
	uint8_t data[16] LION_ATTR_ALIGNED(4) = {
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x10, 0x11, 0x12,
		0x13, 0x14, 0x15, 0x16,
	};

	uint32_t data_address = (uint32_t) data;

	debug_log("flash_address = 0x%08" PRIx32 nl, flash_address);
	debug_log("data_address = 0x%08" PRIx32 nl, data_address);

	uint8_t first_byte = *((uint8_t *) (flash_address));

	debug_log("first_byte = 0x%02" wPRIx8 nl, first_byte);

	status = HAL_FLASH_Unlock();
	if (status != HAL_OK) {
		error_log(red("HAL_FLASH_Unlock failed") nl);
		return;
	}
	status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, flash_address, data_address);
	if (status != HAL_OK) {
		error_log(red("HAL_FLASH_Program failed") nl);
		return;
	}
	FLASH_EraseInitTypeDef erase_info = {
		.TypeErase = FLASH_TYPEERASE_SECTORS,
		// FLASH_BANK_1, FLASH_BANK_2, FLASH_BANK_BOTH
		.Banks = FLASH_BANK_2,
		.Sector = 0, // note that the HAL includes the FLASH_SECTOR_0 - FLASH_SECTOR_31 definitions
		.NbSectors = 1,
	};
	const uint32_t t1 = HAL_GetTick();
	// sector_error will be set by the HAL_FLASHEx_Erase() call to the first sector that could not be erased
	// or to 0xFFFFFFFFU when all sectors were successfully erased
	// not much relevant for our use, when we erase only one sector (.NbSectors = 1)
	uint32_t sector_error;
	status = HAL_FLASHEx_Erase(&erase_info, &sector_error);
	if (status != HAL_OK) {
		error_log(red("HAL_FLASHEx_Erase failed") nl);
		return;
	}

	const uint32_t t2 = HAL_GetTick();

	info_log("done in %" PRIu32 " ms" nl, t2 - t1);

}

void app_test_flash_high_cycling(void) {
	info_log(cyan("app_test_flash_high_cycling") nl);

	HAL_StatusTypeDef status;

	// FLASH_TYPEPROGRAM_QUADWORD
	// FLASH_TYPEPROGRAM_HALFWORD_EDATA
	// FLASH_TYPEPROGRAM_WORD_EDATA

	uint32_t flash_address = FLASH_EDATA_BASE + (FLASH_EDATA_SIZE / 2);
	uint32_t counter = 0xABCDEF12;

	uint32_t data_address = (uint32_t) &counter;

	debug_log("flash_address = 0x%08" PRIx32 nl, flash_address);
	debug_log("data_address = 0x%08" PRIx32 nl, data_address);

	status = HAL_FLASH_Unlock();
	if (status != HAL_OK) {
		error_log(red("HAL_FLASH_Unlock failed") nl);
		return;
	}
	status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD_EDATA, flash_address, data_address);
	if (status != HAL_OK) {
		error_log(red("HAL_FLASH_Program failed") nl);
		return;
	}
	// FLASH_EraseInitTypeDef erase_info = {
	// 	.TypeErase = FLASH_TYPEERASE_SECTORS,
	// 	// FLASH_BANK_1, FLASH_BANK_2, FLASH_BANK_BOTH
	// 	.Banks = FLASH_BANK_2,
	// 	.Sector = 0, // note that the HAL includes the FLASH_SECTOR_0 - FLASH_SECTOR_31 definitions
	// 	.NbSectors = 1,
	// };
	const uint32_t current_EDATA2R = FLASH->EDATA2R_CUR;
	// alternatively we could use the heavyweight HAL_FLASHEx_OBGetConfig()
	// that reads all option bytes and uses the private function FLASH_OB_GetEDATA()
	debug_log("current_EDATA2R = %08" PRIx32 nl, current_EDATA2R);
	const uint32_t t1 = HAL_GetTick();
	// //
	// FLASH_OBProgramInitTypeDef ob_init ={
	// 	.OptionType = OPTIONBYTE_EDATA,
	// 	.Banks = FLASH_BANK_2,
	// 	.EDATASize = 8,
	// };
	// status = HAL_FLASH_OB_Unlock();
	// if (status != HAL_OK) {
	// 	error_log(red("HAL_FLASH_OB_Unlock failed") nl);
	// 	return;
	// }
	// status = HAL_FLASHEx_OBProgram(&ob_init);
	// if (status != HAL_OK) {
	// 	error_log(red("HAL_FLASHEx_OBProgram failed") nl);
	// 	return;
	// }
	// status = HAL_FLASH_OB_Launch();
	// if (status != HAL_OK) {
	// 	error_log(red("HAL_FLASH_OB_Launch failed") nl);
	// 	return;
	// }
	// RM0481 7.4.3 Option bytes modification Option bytes modification sequence
	// recommends: "Reset the device. This step is always recommended."
	// NVIC_SystemReset();

	// FLASH_EraseInitTypeDef erase_info = {
	// 	.TypeErase = FLASH_TYPEERASE_SECTORS,
	// 	// FLASH_BANK_1, FLASH_BANK_2, FLASH_BANK_BOTH
	// 	.Banks = FLASH_BANK_2,
	// 	.Sector = 24, // note that the HAL includes the FLASH_SECTOR_0 - FLASH_SECTOR_31 definitions
	// 	.NbSectors = 1,
	// };
	// // // sector_error will be set by the HAL_FLASHEx_Erase() call to the first sector that could not be erased
	// // // or to 0xFFFFFFFFU when all sectors were successfully erased
	// // // not much relevant for our use, when we erase only one sector (.NbSectors = 1)
	// uint32_t sector_error;
	// status = HAL_FLASHEx_Erase(&erase_info, &sector_error);
	// if (status != HAL_OK) {
	// 	error_log(red("HAL_FLASHEx_Erase failed") nl);
	// 	return;
	// }

	// RM0481 7.3.4 FLASH read operations, Read operation overview,
	//   Read access to OTP, RO and flash high-cycle data operates as follows:
	//   ... 4. If the application reads an OTP data or flash high-cycle data not previously written,
	//          a double ECC error is reported and only a word full of set bits is returned
	//          (see Section 7.3.9 for details). The read data (in 16 bits) is stored in FLASH_ECCDR register,
	//          so that the user can identify if the double ECC error is due to a virgin data or a real ECC error.

	uint32_t first = *((uint32_t *) (flash_address));
	debug_log("first = 0x%08" PRIx32 nl, first);

	const uint32_t t2 = HAL_GetTick();

	info_log("done in %" PRIu32 " ms" nl, t2 - t1);

}

void app_test_signature_counter(void) {
	info_log(cyan("app_test_signature_counter") nl);
	const uint32_t t1 = HAL_GetTick();
	uint32_t counter_new_value;
	if (app_storage.increment_counter(&app_storage, 1, &counter_new_value) != CTAP_STORAGE_OK) {
		error_log(red("app_storage.increment_counter() failed") nl);
	}
	const uint32_t t2 = HAL_GetTick();
	info_log("done in %" PRIu32 " ms" nl, t2 - t1);
}

void app_test_rng_tinymt(void) {
	info_log(cyan("app_test_rng_tinymt") nl);
	uint8_t random_test_buffer[1024];
	const uint32_t t1 = HAL_GetTick();
	const ctap_crypto_status_t status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		random_test_buffer, sizeof(random_test_buffer)
	);
	const uint32_t t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("generated" nl);
	} else {
		error_log("error while generating" nl);
	}
	dump_hex(random_test_buffer, sizeof(random_test_buffer));
	info_log("done in %" PRIu32 " ms" nl, t2 - t1);
}

void app_test_rng_hw(void) {
	info_log(cyan("app_test_rng_hw") nl);
	uint8_t random_test_buffer[1024];
	const uint32_t t1 = HAL_GetTick();
	const ctap_crypto_status_t status = app_hw_crypto.rng_generate_data(
		&app_hw_crypto,
		random_test_buffer, sizeof(random_test_buffer)
	);
	const uint32_t t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("generated" nl);
	} else {
		error_log("error while generating" nl);
	}
	dump_hex(random_test_buffer, sizeof(random_test_buffer));
	info_log("done in %" PRIu32 " ms" nl, t2 - t1);
}

void app_test_ecc_sign(void) {

	info_log(cyan("app_test_ecc_sign") nl);

	ctap_crypto_status_t status;
	uint32_t t1;
	uint32_t t2;

	status = app_sw_crypto.rng_init(&app_sw_crypto, 0);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_init failed") nl);
		return;
	}

	uint8_t private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		private_key,
		sizeof(private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(private_key) failed") nl);
		return;
	}
	debug_log("private_key" nl);
	dump_hex(private_key, sizeof(private_key));

	uint8_t message_hash[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		message_hash,
		sizeof(message_hash)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(message_hash) failed") nl);
		return;
	}
	debug_log("message_hash" nl);
	dump_hex(message_hash, sizeof(message_hash));

	uint8_t public_key[64];
	status = app_hw_crypto.ecc_secp256r1_compute_public_key(
		&app_hw_crypto,
		private_key,
		public_key
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("ecc_secp256r1_compute_public_key failed") nl);
		return;
	}
	debug_log("public_key" nl);
	dump_hex(public_key, sizeof(public_key));

	const uint8_t fixed_k[32] = {
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0
	};

	// const uint8_t fixed_k[32] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

	uint8_t sw_signature[64]; // r (32 bytes) || s (32 bytes)
	uint8_t hw_signature[64]; // r (32 bytes) || s (32 bytes)

	t1 = HAL_GetTick();
	status = app_sw_crypto.ecc_secp256r1_sign(
		&app_sw_crypto,
		private_key,
		message_hash,
		sizeof(message_hash),
		sw_signature,
		fixed_k
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("sw ecc_secp256r1_sign failed") nl);
	}
	debug_log("sw signature" nl);
	dump_hex(sw_signature, sizeof(sw_signature));
	info_log("sw took %" PRIu32 " ms" nl, t2 - t1);

	t1 = HAL_GetTick();
	status = app_hw_crypto.ecc_secp256r1_sign(
		&app_hw_crypto,
		private_key,
		message_hash,
		sizeof(message_hash),
		hw_signature,
		fixed_k
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("hw ecc_secp256r1_sign failed") nl);
	}
	debug_log("hw signature" nl);
	dump_hex(hw_signature, sizeof(hw_signature));
	info_log("hw took %" PRIu32 " ms" nl, t2 - t1);

	if (memcmp(sw_signature, hw_signature, 64) != 0) {
		error_log(red("sw and hw signature differs") nl);
	}

	// int result;
	// #include <uECC.h>
	// t1 = HAL_GetTick();
	// result = uECC_verify(
	// 	public_key,
	// 	message_hash,
	// 	sizeof(message_hash),
	// 	sw_signature,
	// 	uECC_secp256r1()
	// );
	// t2 = HAL_GetTick();
	// if (result != 1) {
	// 	error_log(red("uECC_verify failed to verify sw-generated signature") nl);
	// }
	// info_log("uECC_verify took %" PRIu32 " ms" nl, t2 - t1);
	//
	//
	// t1 = HAL_GetTick();
	// result = uECC_verify(
	// 	public_key,
	// 	message_hash,
	// 	sizeof(message_hash),
	// 	hw_signature,
	// 	uECC_secp256r1()
	// );
	// t2 = HAL_GetTick();
	// if (result != 1) {
	// 	error_log(red("uECC_verify failed to verify hw-generated signature") nl);
	// }
	// info_log("uECC_verify took %" PRIu32 " ms" nl, t2 - t1);

}

void app_test_ecc_compute_public_key(void) {

	info_log(cyan("app_test_ecc_compute_public_key") nl);

	ctap_crypto_status_t status;
	uint32_t t1;
	uint32_t t2;

	status = app_sw_crypto.rng_init(&app_sw_crypto, 0);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_init failed") nl);
		return;
	}

	uint8_t private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		private_key,
		sizeof(private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(private_key) failed") nl);
		return;
	}
	debug_log("private_key" nl);
	dump_hex(private_key, sizeof(private_key));

	uint8_t sw_public_key[64];
	uint8_t hw_public_key[64];

	t1 = HAL_GetTick();
	status = app_sw_crypto.ecc_secp256r1_compute_public_key(
		&app_sw_crypto,
		private_key,
		sw_public_key
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("sw ecc_secp256r1_compute_public_key failed") nl);
	}
	debug_log("sw_public_key" nl);
	dump_hex(sw_public_key, sizeof(sw_public_key));
	info_log("sw took %" PRIu32 " ms" nl, t2 - t1);

	t1 = HAL_GetTick();
	status = app_hw_crypto.ecc_secp256r1_compute_public_key(
		&app_hw_crypto,
		private_key,
		hw_public_key
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("hw ecc_secp256r1_compute_public_key failed") nl);
		return;
	}
	debug_log("hw_public_key" nl);
	dump_hex(hw_public_key, sizeof(hw_public_key));
	info_log("hw took %" PRIu32 " ms" nl, t2 - t1);

	if (memcmp(sw_public_key, hw_public_key, 64) != 0) {
		error_log(red("sw and hw signature differs") nl);
	}

}

void app_test_ecc_shared_secret(void) {

	info_log(cyan("app_test_ecc_shared_secret") nl);

	ctap_crypto_status_t status;
	uint32_t t1;
	uint32_t t2;

	status = app_sw_crypto.rng_init(&app_sw_crypto, 0);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_init failed") nl);
		return;
	}

	uint8_t peer_private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		peer_private_key,
		sizeof(peer_private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(peer_private_key) failed") nl);
		return;
	}
	debug_log("peer_private_key" nl);
	dump_hex(peer_private_key, sizeof(peer_private_key));

	uint8_t peer_public_key[64];
	status = app_sw_crypto.ecc_secp256r1_compute_public_key(
		&app_sw_crypto,
		peer_private_key,
		peer_public_key
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("ecc_secp256r1_compute_public_key(peer_private_key) failed") nl);
		return;
	}
	debug_log("peer_public_key" nl);
	dump_hex(peer_public_key, sizeof(peer_public_key));

	// This is a valid point on the secp256r1 (aka P-256 aka prime256v1) curve.
	// uint8_t peer_public_key[64] = {
	// 	0xbc,0xfd,0x95,0xdb,0x7b,0xe6,0x4d,0x2d,
	// 	0xc1,0x9d,0x45,0x0b,0x87,0x63,0x5f,0x9d,
	// 	0xfc,0x5a,0x4a,0x7c,0x87,0x2c,0x3a,0x66,
	// 	0xcc,0x98,0xe2,0xf7,0x24,0x79,0x90,0x95,
	// 	0xd5,0x5c,0x36,0x41,0xe9,0x9a,0x6c,0xa1,
	// 	0xeb,0xe9,0xbc,0x66,0x00,0xdf,0x3d,0xe0,
	// 	0xf2,0xe3,0xbe,0x33,0x43,0x59,0xc7,0x42,
	// 	0x2b,0xff,0x87,0x3f,0x34,0x1f,0x37,0x9b
	// };

	// // random public key will be most probably invalid
	// // a valid public key is a point (x, y) that lies on the curve (it satisfies the curve equation)
	// uint8_t peer_public_key[64];
	// status = app_sw_crypto.rng_generate_data(
	// 	&app_sw_crypto,
	// 	peer_public_key,
	// 	sizeof(peer_public_key)
	// );
	// if (status != CTAP_CRYPTO_OK) {
	// 	error_log(red("rng_generate_data(peer_public_key) failed") nl);
	// 	return;
	// }
	// debug_log("peer_public_key" nl);
	// dump_hex(peer_public_key, sizeof(peer_public_key));

	uint8_t private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		private_key,
		sizeof(private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(private_key) failed") nl);
		return;
	}
	debug_log("private_key" nl);
	dump_hex(private_key, sizeof(private_key));

	uint8_t sw_shared_secret[32];
	uint8_t hw_shared_secret[32];

	t1 = HAL_GetTick();
	status = app_sw_crypto.ecc_secp256r1_shared_secret(
		&app_sw_crypto,
		peer_public_key,
		private_key,
		sw_shared_secret
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("sw ecc_secp256r1_shared_secret failed") nl);
	}
	debug_log("sw_shared_secret" nl);
	dump_hex(sw_shared_secret, sizeof(sw_shared_secret));
	info_log("sw took %" PRIu32 " ms" nl, t2 - t1);

	t1 = HAL_GetTick();
	status = app_hw_crypto.ecc_secp256r1_shared_secret(
		&app_hw_crypto,
		peer_public_key,
		private_key,
		hw_shared_secret
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("hw ecc_secp256r1_shared_secret failed") nl);
		return;
	}
	debug_log("hw_shared_secret" nl);
	dump_hex(hw_shared_secret, sizeof(hw_shared_secret));
	info_log("hw took %" PRIu32 " ms" nl, t2 - t1);

	if (memcmp(sw_shared_secret, hw_shared_secret, 32) != 0) {
		error_log(red("sw and hw shared secrets differs") nl);
	}

}

void app_test_aes(void) {

	info_log(cyan("app_test_rng_hw") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t random_iv[CTAP_CRYPTO_AES_BLOCK_SIZE];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_iv, sizeof(random_iv));
	debug_log("iv: ");
	dump_hex(random_iv, sizeof(random_iv));

	uint8_t random_key[CTAP_CRYPTO_AES_256_KEY_SIZE];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_key, sizeof(random_key));
	debug_log("key: ");
	dump_hex(random_key, sizeof(random_key));

	const size_t test_size = CTAP_CRYPTO_AES_BLOCK_SIZE * 3;
	uint8_t random_plaintext[test_size];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_plaintext, test_size);
	debug_log("plaintext: ");
	dump_hex(random_plaintext, test_size);

	uint8_t data_sw[test_size];
	memcpy(data_sw, random_plaintext, test_size);

	uint8_t data_hw[test_size];
	memcpy(data_hw, random_plaintext, test_size);

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.aes_256_cbc_encrypt(
		&app_sw_crypto,
		random_iv, random_key, data_sw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw encrypt ok" nl);
	} else {
		error_log(red("error while sw encrypt") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_sw, test_size);

	t1 = HAL_GetTick();
	status = app_hw_crypto.aes_256_cbc_encrypt(
		&app_hw_crypto,
		random_iv, random_key, data_hw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw encrypt ok" nl);
	} else {
		error_log(red("error while hw encrypt") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_hw, test_size);

	if (memcmp(data_sw, data_hw, test_size) != 0) {
		error_log(red("ciphertexts mismatch") nl);
	} else {
		debug_log(green("ciphertexts equal") nl);
	}

	t1 = HAL_GetTick();
	status = app_sw_crypto.aes_256_cbc_decrypt(
		&app_sw_crypto,
		random_iv, random_key, data_sw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw decrypt ok" nl);
	} else {
		error_log(red("error while sw decrypt") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_sw, test_size);

	t1 = HAL_GetTick();
	status = app_hw_crypto.aes_256_cbc_decrypt(
		&app_hw_crypto,
		random_iv, random_key, data_hw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw decrypt ok" nl);
	} else {
		error_log(red("error while hw decrypt") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_hw, test_size);

	if (memcmp(data_sw, data_hw, test_size) != 0) {
		error_log(red("plaintexts mismatch") nl);
	} else {
		debug_log(green("plaintexts equal") nl);
	}

}

void app_test_hash_zero(void) {

	info_log(cyan("app_test_hash_zero") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data[1]; // zero-length variable-length arrays are not allowed

	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.sha256_compute_digest(
		&app_sw_crypto,
		data, 0,
		hash_sw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while sw sha256_compute_digest") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	status = app_hw_crypto.sha256_compute_digest(
		&app_hw_crypto,
		data, 0,
		hash_hw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while hw sha256_compute_digest") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}

void app_test_hash_big(void) {

	info_log(cyan("app_test_hash_big") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data[333];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data, sizeof(data));
	debug_log("data: ");
	dump_hex(data, sizeof(data));


	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.sha256_compute_digest(
		&app_sw_crypto,
		data, sizeof(data),
		hash_sw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while sw sha256_compute_digest") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	status = app_hw_crypto.sha256_compute_digest(
		&app_hw_crypto,
		data, sizeof(data),
		hash_hw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while hw sha256_compute_digest") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}

void app_test_hash_big_two_parts(void) {

	info_log(cyan("app_test_hash_big") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data1[49];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data1, sizeof(data1));
	debug_log("data1: ");
	dump_hex(data1, sizeof(data1));
	uint8_t data2[87];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data2, sizeof(data2));
	debug_log("data2: ");
	dump_hex(data2, sizeof(data2));


	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;

	t1 = HAL_GetTick();
	const hash_alg_t *const sw_sha256 = app_sw_crypto.sha256;
	uint8_t sw_sha256_ctx[sw_sha256->ctx_size];
	app_sw_crypto.sha256_bind_ctx(&app_sw_crypto, sw_sha256_ctx);
	sw_sha256->init(sw_sha256_ctx);
	sw_sha256->update(sw_sha256_ctx, data1, sizeof(data1));
	sw_sha256->update(sw_sha256_ctx, data2, sizeof(data2));
	sw_sha256->final(sw_sha256_ctx, hash_sw);
	t2 = HAL_GetTick();
	// if (status == CTAP_CRYPTO_OK) {
	// 	info_log("sw sha256_compute_digest ok" nl);
	// } else {
	// 	error_log(red("error while sw sha256_compute_digest") nl);
	// }
	info_log("sw done in %" PRIu32 " ms, sizeof(sw_sha256_ctx) = %" PRIsz nl, t2 - t1, sizeof(sw_sha256_ctx));
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	const hash_alg_t *const hw_sha256 = app_hw_crypto.sha256;
	uint8_t hw_sha256_ctx[hw_sha256->ctx_size];
	app_hw_crypto.sha256_bind_ctx(&app_hw_crypto, hw_sha256_ctx);
	hw_sha256->init(hw_sha256_ctx);
	hw_sha256->update(hw_sha256_ctx, data1, sizeof(data1));
	hw_sha256->update(hw_sha256_ctx, data2, sizeof(data2));
	hw_sha256->final(hw_sha256_ctx, hash_hw);
	t2 = HAL_GetTick();
	// if (status == CTAP_CRYPTO_OK) {
	// 	info_log("hw sha256_compute_digest ok" nl);
	// } else {
	// 	error_log(red("error while hw sha256_compute_digest") nl);
	// }
	info_log("hw done in %" PRIu32 " ms, sizeof(hw_sha256_ctx) = %" PRIsz nl, t2 - t1, sizeof(hw_sha256_ctx));
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}
