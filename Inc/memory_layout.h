#ifndef POKUSEW_MEMORY_LAYOUT_H
#define POKUSEW_MEMORY_LAYOUT_H

#include "flash.h"
#include "storage.h"

// STM32F407IGH6 has 1024 KB of Flash memory
// mapped to memory address range 0x0800_0000 - 0x080F_FFFF
// see Section 4, Memory Mapping, in the STM32F407IG datasheet (DS8626)
// A main memory block divided into 12 sectors (with different sizes)
// - 4 sectors of  16 KB: sectors   0-3
// - 1 sector  of  64 KB: sector      4
// - 7 sectors of 128 KB: sectors: 5-11
// 4*16+64+7*128 = 1024

// To simplify the design, let's use only the 7 128-KB sectors.

#define STATE_BACKUP_SECTOR 11
#define STATE_SECTOR 10
#define STATE_SECTOR_NUM_SLOTS (SECTOR_128KB_SIZE / sizeof(AuthenticatorState))
static_assert(
	(STATE_SECTOR_NUM_SLOTS * sizeof(AuthenticatorState) + sizeof(uint32_t) <= SECTOR_128KB_SIZE),
	"not enough space for magic in STATE_SECTOR"
);
#define MAGIC_ADDR (flash_128KB_sector_to_addr(STATE_SECTOR + 1) - 4)
#define MAGIC (0xD7E60002u)

#define COUNTER_COUNTS_PER_DATA_SECTOR (SECTOR_128KB_SIZE / 4)
#define COUNTER_DATA_SECTOR 9
#define COUNTER_NUM_ERASES_SECTOR 8

#include "assert.h"
static_assert(sizeof(AuthenticatorState) == 208, "sizeof(AuthenticatorState) must be 204 bytes");
static_assert(sizeof(AuthenticatorState) % sizeof(uint32_t) == 0, "sizeof(AuthenticatorState) must be divisible by 4");

// Storage of FIDO2 resident keys
#define RK_SECTOR 8
#define RK_NUM_KEYS (SECTOR_128KB_SIZE / RK_STORAGE_SIZE)
#define RK_STORAGE_SIZE 512
static_assert(sizeof(CTAP_residentKey) <= RK_STORAGE_SIZE, "sizeof(AuthenticatorState) must be <= 512 bytes");
static_assert(RK_STORAGE_SIZE * RK_NUM_KEYS == SECTOR_128KB_SIZE, "sizeof(AuthenticatorState) must be <= 412 bytes");

#endif // POKUSEW_MEMORY_LAYOUT_H
