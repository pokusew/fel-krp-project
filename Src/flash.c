#include <string.h>

#include "stm32f4xx.h"
#include "flash.h"
#include "main.h"
#include "utils.h"

static void flash_lock(void) {
	HAL_FLASH_Lock();
}

static void flash_unlock(void) {
	if (HAL_FLASH_Unlock() != HAL_OK) {
		Error_Handler();
	}
}

void flash_erase_sector(uint8_t sector) {

	debug_log("flash_erase_sector sector=%" wPRIu8 nl, sector);

	flash_unlock();

	uint32_t error = 0;

	FLASH_EraseInitTypeDef config = {
		.TypeErase = FLASH_TYPEERASE_SECTORS,
		.Banks = 0, // does not apply to sectors erase
		.Sector = sector,
		.NbSectors = 1,
		// note: FLASH_VOLTAGE_RANGE_4 cannot be used in our case because we don't have the external Vpp
		.VoltageRange = FLASH_VOLTAGE_RANGE_3,
	};

	if (HAL_FLASHEx_Erase(&config, &error) != HAL_OK) {
		Error_Handler();
	}

}

void flash_write(uint32_t addr, uint8_t *data, size_t size) {

	// note: FLASH_TYPEPROGRAM_DOUBLEWORD cannot be used because it requires FLASH_VOLTAGE_RANGE_4 (the external Vpp)

	debug_log("flash_write addr=0x%08" PRIx32 " size=%d" nl, addr, size);

	flash_unlock();

	// WORD (32 bytes) align
	// note: this must correspond to the FLASH_TYPEPROGRAM_xxx
	addr &= ~(0x03);

	uint8_t buf[4];
	for (unsigned int i = 0; i < size; i += 4) {
		memmove(buf, data + i, (size - i) > 4 ? 4 : size - i);
		if (size - i < 4) {
			memset(buf + size - i, 0xff, 4 - (size - i));
		}
		if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, addr, *(uint32_t *) buf) != HAL_OK) {
			Error_Handler();
		}
		addr += 4;
	}

}
