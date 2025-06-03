#include "flash_storage.h"
#include "flash.h"
#include "utils.h"
#include <string.h>
#include <stdbool.h>

// TODO:
//   This is a work-in-progress (more like a PoC).
//   Support for multiple sectors, compaction (free space by reordering items and removing the deleted ones),
//   efficient atomic counter (within the high-cycling (EDATA) area) is planned.

#define ctap_storage_check(expr)                 \
    if ((status = (expr)) != CTAP_STORAGE_OK) {  \
        return status;                           \
    }                                            \
    ((void) 0)

#define FLASH_STORAGE_STANDARD_SECTOR_SIZE  (8 * 1024)
#define FLASH_WORD_SIZE    16 // 128 bits

#define FLASH_STORAGE_EDATA_SECTOR_SIZE     (6 * 1024)
#define FLASH_STORAGE_EDATA_WORD_SIZE       4 // 32 bits
#define FLASH_STORAGE_EDATA_NUM_SECTORS     8

#define FLASH_STORAGE_STANDARD_NUM_SECTORS  (32 - FLASH_STORAGE_EDATA_NUM_SECTORS)

#define FLASH_STORAGE_VERSION  1

static const uint8_t delete_marker_data[FLASH_WORD_SIZE] LION_ATTR_ALIGNED(4);

// sector:
//   header (128 bits)
//   delete marker (128 bit)
//   ... items

// item:
//   header (128 bits)
//   delete marker (128 bit)
//   data (0 <= size <= sector_size - 48)
//   [padding to 128-bit boundary]
//   checksum (128 bits)

// flash memory address to sector

typedef struct LION_ATTR_PACKED sector_header {
	uint32_t version;
	uint32_t word_1;
	uint32_t word_2;
	uint32_t word_3;
} sector_header_t;
static_assert(
	sizeof(sector_header_t) == FLASH_WORD_SIZE,
	"sizeof(sector_header_t) == FLASH_WORD_SIZE"
);

typedef struct LION_ATTR_PACKED item_header {
	uint32_t key;
	uint32_t size;
	uint32_t word_2;
	uint32_t word_3;
} item_header_t;
static_assert(
	sizeof(item_header_t) == FLASH_WORD_SIZE,
	"sizeof(item_header_t) == FLASH_WORD_SIZE"
);

typedef struct LION_ATTR_PACKED item_checksum {
	uint32_t word_0;
	uint32_t word_1;
	uint32_t word_2;
	uint32_t crc32;
} item_checksum_t;
static_assert(
	sizeof(item_checksum_t) == FLASH_WORD_SIZE,
	"sizeof(item_checksum_t) == FLASH_WORD_SIZE"
);

LION_ATTR_ALWAYS_INLINE static inline uint32_t handle_to_address(const uint32_t handle) {
	return handle;
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t address_to_handle(const uint32_t address) {
	return address;
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t ceil_size_to_boundary(const size_t size) {
	static_assert((((0) + 15) & (~0xFu)) == 0, "ceil_size_to_boundary()");
	static_assert((((1) + 15) & (~0xFu)) == 16, "ceil_size_to_boundary()");
	static_assert((((2) + 15) & (~0xFu)) == 16, "ceil_size_to_boundary()");
	static_assert((((3) + 15) & (~0xFu)) == 16, "ceil_size_to_boundary()");
	static_assert((((16) + 15) & (~0xFu)) == 16, "ceil_size_to_boundary()");
	static_assert((((17) + 15) & (~0xFu)) == 32, "ceil_size_to_boundary()");
	static_assert((((20) + 15) & (~0xFu)) == 32, "ceil_size_to_boundary()");
	static_assert((((32) + 15) & (~0xFu)) == 32, "ceil_size_to_boundary()");
	static_assert((((33) + 15) & (~0xFu)) == 48, "ceil_size_to_boundary()");
	return (size + 15) & (~0xFu);
}

LION_ATTR_ALWAYS_INLINE static inline size_t compute_total_item_size(const size_t size) {
	return (2 * FLASH_WORD_SIZE) + ceil_size_to_boundary(size) + FLASH_WORD_SIZE;
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t sector_base_address(const uint32_t sector) {
	// 32 sectors Bank 1
	// 32 sectors Bank 2
	// we want a sector within Bank 2
	return FLASH_BASE + (32 * FLASH_STORAGE_STANDARD_SECTOR_SIZE) + (sector * FLASH_STORAGE_STANDARD_SECTOR_SIZE);
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t is_virgin_word(const uint32_t *word) {
	uint32_t virgin_word = 0xFFFFFFFF;
	for (int i = 0; i < 4; ++i) {
		virgin_word &= word[i];
	}
	return virgin_word == 0xFFFFFFFF;
}

static ctap_storage_status_t erase_sector(uint32_t sector) {

	assert(sector < FLASH_STORAGE_STANDARD_NUM_SECTORS);

	FLASH_EraseInitTypeDef erase_info = {
		.TypeErase = FLASH_TYPEERASE_SECTORS,
		// FLASH_BANK_1, FLASH_BANK_2, FLASH_BANK_BOTH
		.Banks = FLASH_BANK_2,
		.Sector = sector, // note that the HAL includes the FLASH_SECTOR_0 - FLASH_SECTOR_31 definitions
		.NbSectors = 1,
	};
	// sector_error will be set by the HAL_FLASHEx_Erase() call to the first sector that could not be erased
	// or to 0xFFFFFFFFU when all sectors were successfully erased
	// not much relevant for our use, when we erase only one sector (.NbSectors = 1)
	uint32_t sector_error;
	HAL_StatusTypeDef status = HAL_FLASHEx_Erase(&erase_info, &sector_error);
	if (status != HAL_OK) {
		error_log(red("HAL_FLASHEx_Erase failed") nl);
		return CTAP_STORAGE_ERROR;
	}

	return CTAP_STORAGE_OK;

}

static ctap_storage_status_t program_word(uint32_t flash_address, uint32_t data_address) {

	HAL_StatusTypeDef status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD, flash_address, data_address);
	if (status != HAL_OK) {
		error_log(red("HAL_FLASH_Program failed") nl);
		return CTAP_STORAGE_ERROR;
	}

	return CTAP_STORAGE_OK;

}

static ctap_storage_status_t init_sector(uint32_t sector) {

	debug_log("init_sector = %" PRIu32 nl, sector);

	ctap_storage_status_t status;

	const uint32_t sector_base = sector_base_address(sector);

	const sector_header_t *header = (sector_header_t *) (sector_base + 0);
	const uint32_t *delete_marker = (uint32_t *) (sector_base + sizeof(sector_header_t));

	if (header->version != FLASH_STORAGE_VERSION || !is_virgin_word(delete_marker)) {
		debug_log("  erasing dirty sector ..." nl);
		ctap_storage_check(erase_sector(sector));
		sector_header_t new_header = {
			.version = FLASH_STORAGE_VERSION,
		};
		debug_log("  programming new sector header ..." nl);
		ctap_storage_check(program_word(sector_base, (uint32_t) &new_header));
		return CTAP_STORAGE_OK;
	}

	return CTAP_STORAGE_OK;

}

static uint32_t find_write_address(
	const ctap_storage_t *const storage
) {

	ctap_storage_item_t item = {
		.handle = 0u,
		.key = 0u,
	};

	while (stm32h533_flash_storage_find_item(storage, &item) == CTAP_STORAGE_OK) {
		// reset "search criteria" and continue iterating over the items
		item.key = 0u;
	}

	if (item.handle == 0u) {
		return sector_base_address(0) + (2 * FLASH_WORD_SIZE);
	}

	return handle_to_address(item.handle) + compute_total_item_size(item.size);

}

ctap_storage_status_t stm32h533_flash_storage_init(
	const ctap_storage_t *const storage
) {

	debug_log("stm32h533_flash_storage_init" nl);

	stm32h533_flash_storage_context_t *context = storage->context;

	if (HAL_FLASH_Unlock() != HAL_OK) {
		error_log(red("HAL_FLASH_Unlock failed") nl);
		return CTAP_STORAGE_ERROR;
	}

	if (init_sector(0) != CTAP_STORAGE_OK) {
		return CTAP_STORAGE_ERROR;
	}

	context->write_address = find_write_address(storage);
	const uint32_t max_address = sector_base_address(1);

	info_log(
		"flash_storage: write_address = 0x%08" PRIx32 ", remaining size = %" PRIu32 nl,
		context->write_address, max_address - context->write_address
	);

	return CTAP_STORAGE_OK;

}

ctap_storage_status_t stm32h533_flash_storage_find_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	// debug_log(
	// 	"stm32h533_flash_storage_find_item: key = %" PRIu32 ", handle = 0x%08" PRIx32 nl,
	// 	item->key, item->handle
	// );

	stm32h533_flash_storage_context_t *context = storage->context;

	lion_unused(context); // for now

	const uint32_t min_address = sector_base_address(0) + (2 * FLASH_WORD_SIZE);
	const uint32_t max_address = sector_base_address(1);

	uint32_t address = min_address;

	// continue iteration
	if (item->handle != 0u) {
		address = handle_to_address(item->handle) + compute_total_item_size(item->size);
		assert(min_address <= address && address < max_address);
	}

	while (address < max_address) {

		// debug_log("  address = 0x%08" PRIx32 nl, address);

		const item_header_t *const header = (const item_header_t *) (address);
		const uint32_t *const delete_marker = (const uint32_t *) (address + FLASH_WORD_SIZE);
		const uint8_t *const data = (const uint8_t *) (address + (2 * FLASH_WORD_SIZE));

		if (is_virgin_word((const uint32_t *) header)) {
			// debug_log("  virgin header reached" nl);
			break;
		}

		// TODO: check checksum
		// const item_checksum_t *const checksum = (const item_checksum_t *) (
		// 	address + 2 * FLASH_WORD_SIZE + ceil_size_to_boundary(header->size)
		// );

		if (is_virgin_word(delete_marker) && (item->key == 0u || item->key == header->key)) {
			item->handle = address_to_handle(address);
			item->key = header->key;
			item->size = header->size;
			item->data = data;
			return CTAP_STORAGE_OK;
		}

		// next item
		debug_log("  next item" nl);
		address += compute_total_item_size(header->size);

	}

	return CTAP_STORAGE_ITEM_NOT_FOUND;

}

static ctap_storage_status_t stm32h533_flash_storage_create_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	debug_log(
		"stm32h533_flash_storage_create_item: key = %" PRIu32 ", size = %" PRIsz nl,
		item->key, item->size
	);

	ctap_storage_status_t status;

	assert(item->key != 0u);
	assert(item->size == 0u || item->data != NULL);

	stm32h533_flash_storage_context_t *context = storage->context;

	const size_t total_item_size = compute_total_item_size(item->size);

	const uint32_t max_address = sector_base_address(1);

	if (context->write_address + total_item_size > max_address) {
		// TODO: implement compaction
		error_log(red("stm32h533_flash_storage_create_item: out of memory") nl);
		return CTAP_STORAGE_OUT_OF_MEMORY_ERROR;
	}

	const uint32_t item_address = context->write_address;

	item_header_t header = {
		.key = item->key,
		.size = item->size,
		.word_2 = 0,
		.word_3 = 0,
	};
	item_checksum_t checksum = {
		.word_0 = 0,
		.word_1 = 0,
		.word_2 = 0,
		.crc32 = 1, // TODO
	};

	ctap_storage_check(program_word(item_address, (uint32_t) &header));

	// keep virgin word for the delete marker

	// write data
	const uint32_t aligned_size = ceil_size_to_boundary(item->size);
	size_t i = 0;
	for (; (i + FLASH_WORD_SIZE) <= item->size; i += FLASH_WORD_SIZE) {
		ctap_storage_check(program_word(
			item_address + (2 * FLASH_WORD_SIZE) + i,
			(uint32_t) &item->data[i]
		));
	}
	if (i < aligned_size) {
		assert(aligned_size - item->size < FLASH_WORD_SIZE);
		uint8_t last_word[FLASH_WORD_SIZE] LION_ATTR_ALIGNED(4);
		memcpy(last_word, &item->data[i], item->size - i);
		memset(&last_word[item->size - i], 0xFF, aligned_size - item->size);
		ctap_storage_check(program_word(
			item_address + (2 * FLASH_WORD_SIZE) + i,
			(uint32_t) last_word
		));
		i += FLASH_WORD_SIZE;
	}
	assert(i == aligned_size);

	ctap_storage_check(program_word(item_address + (2 * FLASH_WORD_SIZE) + aligned_size, (uint32_t) &checksum));

	// update the item
	item->handle = address_to_handle(item_address);
	item->data = (const uint8_t *) (item_address + (2 * FLASH_WORD_SIZE));

	context->write_address += total_item_size;

	debug_log("new write_address = 0x%08" PRIx32 nl, context->write_address);

	return CTAP_STORAGE_OK;

}

ctap_storage_status_t stm32h533_flash_storage_create_or_update_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	ctap_storage_status_t status;

	assert(item->key != 0u);

	if (item->handle != 0u) {
		ctap_storage_item_t new_item = *item;
		ctap_storage_check(stm32h533_flash_storage_create_item(storage, &new_item));
		ctap_storage_check(stm32h533_flash_storage_delete_item(storage, item->handle));
		*item = new_item;
		return CTAP_STORAGE_OK;
	}

	return stm32h533_flash_storage_create_item(storage, item);

}

ctap_storage_status_t stm32h533_flash_storage_delete_item(
	const ctap_storage_t *const storage,
	const uint32_t item_handle
) {

	stm32h533_flash_storage_context_t *context = storage->context;

	assert(item_handle > 0);

	const uint32_t item_address = handle_to_address(item_handle);

	debug_log("stm32h533_flash_storage_delete_item: item_address = 0x%08" PRIx32 nl, item_address);

	const uint32_t min_address = sector_base_address(0) + (2 * FLASH_WORD_SIZE);

	assert(min_address <= item_address && item_address < context->write_address);

	return program_word(item_address + FLASH_WORD_SIZE, (uint32_t) delete_marker_data);

}

ctap_storage_status_t stm32h533_flash_storage_increment_counter(
	const ctap_storage_t *const storage,
	const uint32_t increment,
	uint32_t *const counter_new_value
) {

	// The signature counter is not strictly mandatory.
	// Until we implement a more efficient counter storage (using the EDATA area (high-cycling area)),
	// we could just disable the signature counter feature (i.e., always return 0 which signals
	// to the RP that the signature counter is not supported).
	//
	// lion_unused(storage);
	// lion_unused(increment);
	//
	// *counter_new_value = 0;
	//
	// return CTAP_STORAGE_OK;

	ctap_storage_item_t item = {
		.handle = 0u,
		.key = CTAP_STORAGE_KEY_GLOBAL_SIGNATURE_COUNTER,
	};

	uint32_t tmp_counter_value = 0u;

	if (stm32h533_flash_storage_find_item(storage, &item) == CTAP_STORAGE_OK) {
		assert(item.size == sizeof(uint32_t));
		tmp_counter_value = *((uint32_t *) item.data);
	}

	tmp_counter_value += increment;

	item.size = sizeof(uint32_t);
	item.data = (const uint8_t *) &tmp_counter_value;

	if (stm32h533_flash_storage_create_or_update_item(storage, &item) == CTAP_STORAGE_OK) {
		*counter_new_value = *((uint32_t *) item.data);
		assert(*counter_new_value == tmp_counter_value);
		debug_log(
			"stm32h533_flash_storage_increment_counter" nl
			"  counter_new_value = %" PRIu32 nl,
			*counter_new_value
		);
		return CTAP_STORAGE_OK;
	}

	return CTAP_STORAGE_ERROR;

}

size_t stm32h533_flash_storage_estimate_num_remaining_items(
	const ctap_storage_t *const storage,
	const ctap_storage_item_t *const item
) {

	stm32h533_flash_storage_context_t *context = storage->context;

	const size_t total_item_size = compute_total_item_size(item->size);
	const size_t remaining_memory_size = sector_base_address(1) - context->write_address;

	return remaining_memory_size / total_item_size;

}

ctap_storage_status_t stm32h533_flash_storage_erase(
	const ctap_storage_t *const storage
) {

	debug_log("stm32h533_flash_storage_erase" nl);

	stm32h533_flash_storage_context_t *context = storage->context;

	if (context->write_address == (FLASH_WORD_SIZE * 2)) {
		debug_log("skipping storage erase" nl);
		return CTAP_STORAGE_OK;
	}

	ctap_storage_status_t status;

	ctap_storage_check(program_word(
		sector_base_address(0) + FLASH_WORD_SIZE,
		(uint32_t) delete_marker_data
	));

	return stm32h533_flash_storage_init(storage);

}
