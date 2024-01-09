#include "utils.h"
#include "usb_device.h"
#include "usbd_custom_hid_if.h"
#include "device.h"
#include "fifo.h"
#include "flash.h"
#include "memory_layout.h"
#include "log.h"

uint32_t millis() {
	return HAL_GetTick();
}

void usbhid_send(uint8_t *msg) {
	while (true) {
		uint8_t status = USBD_CUSTOM_HID_SendReport(&hUsbDeviceFS, msg, 64);

		if (status == USBD_OK) {
			debug_log("solo usbhid_send ok" nl);
			return;
		}

		if (status == USBD_BUSY) {
			debug_log("solo usbhid_send busy" nl);
			HAL_Delay(1);
			// TODO: limit max number of repeats
			continue;
		}

		debug_log("solo usbhid_send fail status = %" wPRIu8 nl, status);
		exit(1);
	}
}

static uint8_t r = 0;

int ctap_generate_rng(uint8_t *dst, size_t num) {
	// rng_get_bytes(dst, num);
	// return 1;
	// TODO: use STM32's HW generator
	int i;
	for (i = 0; i < num; i++) {
		dst[i] = ++r;
	}
	return 1;
}

int usbhid_recv(uint8_t *msg) {
	__disable_irq();
	size_t size = RingBuffer_GetDataLength(&hidmsg_buffer);
	assert(size % 64 == 0);
	if (size > 0) {
		// debug_log("%" PRIu32 nl, size);
		size_t read = RingBuffer_Read(&hidmsg_buffer, msg, 64);
		assert(read == 64);
		// printf1(TAG_DUMP2,">> ");
		// dump_hex1(TAG_DUMP2,msg, HID_PACKET_SIZE);
		__enable_irq();
		return 64;
	}
	__enable_irq();
	return 0;
}

static int authenticator_is_backup_initialized(void) {
	debug_log(yellow("authenticator_is_backup_initialized") nl);
	uint8_t header[16];
	uint32_t *ptr = (uint32_t *) flash_128KB_sector_to_addr(STATE2_SECTOR);
	memmove(header, ptr, 16);
	AuthenticatorState *state = (AuthenticatorState *) header;
	return state->is_initialized == INITIALIZED_MARKER;
}

// int authenticator_read_state(AuthenticatorState *a) {
// 	debug_log(yellow("authenticator_read_state") nl);
// 	uint32_t *ptr = (uint32_t *) flash_128KB_sector_to_addr(STATE1_SECTOR);
// 	memmove(a, ptr, sizeof(AuthenticatorState));
//
// 	if (a->is_initialized != INITIALIZED_MARKER) {
//
// 		if (authenticator_is_backup_initialized()) {
// 			debug_log("Warning: memory corruption detected. Restoring from backup..." nl);
// 			ptr = (uint32_t *) flash_128KB_sector_to_addr(STATE2_SECTOR);
// 			memmove(a, ptr, sizeof(AuthenticatorState));
// 			authenticator_write_state(a);
// 			debug_log(yellow("initialized from backup") nl);
// 			return 1;
// 		}
//
// 		debug_log(yellow("not initialized") nl);
// 		return 0;
// 	}
//
// 	debug_log(yellow("initialized from primary") nl);
// 	return 1;
// }
//
//
// void authenticator_write_state(AuthenticatorState *a) {
// 	debug_log(yellow("authenticator_write_state pin=%d") nl, a->is_pin_set);
// 	timestamp();
// 	flash_erase_sector(STATE1_SECTOR);
// 	flash_write(flash_128KB_sector_to_addr(STATE1_SECTOR), (uint8_t *) a, sizeof(AuthenticatorState));
//
// 	flash_erase_sector(STATE2_SECTOR);
// 	flash_write(flash_128KB_sector_to_addr(STATE2_SECTOR), (uint8_t *) a, sizeof(AuthenticatorState));
// 	debug_log(green("authenticator_write_state done in %" PRId32 " ms") nl, timestamp());
// }

uint32_t ctap_atomic_count(uint32_t amount) {

	debug_log(magenta("ctap_atomic_count amount=%" PRIu32) nl, amount);

	uint32_t *counters = (uint32_t *) flash_128KB_sector_to_addr(COUNTER_DATA_SECTOR);
	uint32_t num_erases = *(uint32_t *) flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR);

	static uint32_t sc = 0;

	if (num_erases == 0xffffffff) {
		debug_log("num_erases == 0xffffffff -> erasing COUNTER_NUM_ERASES_SECTOR" nl);
		num_erases = 1;
		flash_erase_sector(COUNTER_NUM_ERASES_SECTOR);
		flash_write(flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR), (uint8_t *) &num_erases, 4);
	}

	if (amount == 0) {
		// use a random amount in range [1-16]
		uint8_t rng[1];
		ctap_generate_rng(rng, 1);
		amount = (rng[0] & 0x0f) + 1;
		assert(1 <= amount && amount <= 16);
		debug_log("using random amount=%" PRIu32 nl, amount);
	}

	// find the last counter and the first empty offset
	uint32_t last_counter = 0;
	int offset;
	// flash wear leveling (ensure writs/erase cycles are distributed evenly)
	// note: change to `offset += 2` in case we use DOUBLE WORDS flash_write
	for (offset = 0; offset < COUNTER_COUNTS_PER_DATA_SECTOR; offset += 1) {

		if (counters[offset] == 0xffffffff) {
			break;
		}

		if (counters[offset] < last_counter) {
			info_log(
				red("ctap_atomic_count: Error, count went down! counters[offset=%d]=%"PRIu32" < last_counter=%" PRIu32) nl,
				offset,
				counters[offset],
				last_counter
			);
		}

		last_counter = counters[offset];
	}

	info_log(
		"num_erases=%" PRIu32 ", last_counter=%" PRIu32 ", offset=%d",
		num_erases,
		last_counter,
		offset
	);

	if (last_counter == 0) {
		info_log(yellow(
			"last_counter == 0"
			"-> power interrupted during previous count (or initialization), restoring..."
		));

		// restore counter value
		last_counter = num_erases * COUNTER_COUNTS_PER_DATA_SECTOR + 1;
		flash_erase_sector(COUNTER_DATA_SECTOR);
		flash_write(flash_128KB_sector_to_addr(COUNTER_DATA_SECTOR), (uint8_t *) &last_counter, 4);

		// increment num_erases
		num_erases++;
		flash_erase_sector(COUNTER_NUM_ERASES_SECTOR);
		flash_write(flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR), (uint8_t *) &num_erases, 4);

		return last_counter;
	}

	// TODO: is this needed?
	if (amount > COUNTER_COUNTS_PER_DATA_SECTOR) {
		last_counter = amount;
	} else {
		last_counter += amount;
	}

	if ((last_counter / COUNTER_COUNTS_PER_DATA_SECTOR) > num_erases) {
		info_log(yellow(
			"detected invalid num_erases value"
			" (probably due to the previous power interruption), restoring..."
		));
		// restore num_erases
		num_erases = last_counter / COUNTER_COUNTS_PER_DATA_SECTOR;
		flash_erase_sector(COUNTER_NUM_ERASES_SECTOR);
		flash_write(flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR), (uint8_t *) &num_erases, 4);
	}

	if (offset == COUNTER_COUNTS_PER_DATA_SECTOR) {
		debug_log("all counters used > erase needed" nl);

		// update num_erases
		num_erases = (last_counter / COUNTER_COUNTS_PER_DATA_SECTOR) + 1;
		flash_erase_sector(COUNTER_NUM_ERASES_SECTOR);
		flash_write(flash_128KB_sector_to_addr(COUNTER_NUM_ERASES_SECTOR), (uint8_t *) &num_erases, 4);

		// erase the counters data and set the new offset at the beginning
		flash_erase_sector(COUNTER_DATA_SECTOR);
		offset = 0;
	}

	// write the incremented value at the offset (which is the first empty offset)
	flash_write(
		flash_128KB_sector_to_addr(COUNTER_DATA_SECTOR) + (offset * 4),
		(uint8_t *) &last_counter,
		4
	);

	if (last_counter == sc) {
		error_log(
			red("ctap_atomic_count: no count detected")
			" last_counter==%lu, num_erases=%lu, offset=%d",
			last_counter,
			num_erases,
			offset
		);
		Error_Handler();
	}

	sc = last_counter;

	return last_counter;
}

//
// void ctap_reset_rk(void) {
// 	int i;
// 	printf1(TAG_GREEN, "resetting RK \r\n");
// 	for (i = 0; i < RK_NUM_PAGES; i++) {
// 		flash_erase_page(RK_START_PAGE + i);
// 	}
// }
//
// static_assert(sizeof(CTAP_residentKey) == 409, "ff");
// static_assert(sizeof(AuthenticatorState) == 208, "ff");
//
//
// uint32_t ctap_rk_size(void) {
// 	return RK_NUM_PAGES * (PAGE_SIZE / sizeof(CTAP_residentKey));
// }
//
// void ctap_store_rk(int index, CTAP_residentKey *rk) {
// 	ctap_overwrite_rk(index, rk);
// }
//
// void ctap_delete_rk(int index) {
// 	CTAP_residentKey rk;
// 	memset(&rk, 0xff, sizeof(CTAP_residentKey));
// 	ctap_overwrite_rk(index, &rk);
// }
//
// void ctap_load_rk(int index, CTAP_residentKey *rk) {
// 	int byte_offset_into_page = (sizeof(CTAP_residentKey) * (index % (PAGE_SIZE / sizeof(CTAP_residentKey))));
// 	int page_offset = (index) / (PAGE_SIZE / sizeof(CTAP_residentKey));
//
// 	uint32_t addr = flash_addr(page_offset + RK_START_PAGE) + byte_offset_into_page;
//
// 	printf1(TAG_GREEN, "reading RK %d @ %04x\r\n", index, addr);
// 	if (page_offset < RK_NUM_PAGES) {
// 		uint32_t *ptr = (uint32_t *) addr;
// 		memmove((uint8_t *) rk, ptr, sizeof(CTAP_residentKey));
// 	} else {
// 		printf2(TAG_ERR, "Out of bounds reading index %d for rk\n", index);
// 	}
// }
//
// void ctap_overwrite_rk(int index, CTAP_residentKey *rk) {
// 	uint8_t tmppage[PAGE_SIZE];
//
// 	int byte_offset_into_page = (sizeof(CTAP_residentKey) * (index % (PAGE_SIZE / sizeof(CTAP_residentKey))));
// 	int page_offset = (index) / (PAGE_SIZE / sizeof(CTAP_residentKey));
//
// 	printf1(TAG_GREEN, "overwriting RK %d @ page %d @ addr 0x%08x-0x%08x\r\n",
// 			index, RK_START_PAGE + page_offset,
// 			flash_addr(RK_START_PAGE + page_offset) + byte_offset_into_page,
// 			flash_addr(RK_START_PAGE + page_offset) + byte_offset_into_page + sizeof(CTAP_residentKey)
// 	);
// 	if (page_offset < RK_NUM_PAGES) {
// 		memmove(tmppage, (uint8_t *) flash_addr(RK_START_PAGE + page_offset), PAGE_SIZE);
//
// 		memmove(tmppage + byte_offset_into_page, rk, sizeof(CTAP_residentKey));
// 		flash_erase_page(RK_START_PAGE + page_offset);
// 		flash_write(flash_addr(RK_START_PAGE + page_offset), tmppage, PAGE_SIZE);
// 	} else {
// 		printf2(TAG_ERR, "Out of bounds reading index %d for rk\n", index);
// 	}
// 	printf1(TAG_GREEN, "4\r\n");
// }
