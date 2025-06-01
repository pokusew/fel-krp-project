#ifndef LIONKEY_STM32H33_FLASH_H
#define LIONKEY_STM32H33_FLASH_H

#include "stm32h5xx_hal.h"
#include <assert.h>

// STM32H533RET6 has 512 KB of embedded flash memory (user main memory) for storing programs and data.
// The memory is divided into two independent banks (Bank 1 and Bank 2).
// Each bank contains 256 KB of user main memory divided into 32 sectors (each sector has a size of 8 KB).
// 2 * 32 * 8 = 512 KB.
// The user main memory block features flash-word rows of 128 bits + 9 bits of ECC per word.

// Flash memory programming
// * by 128 bits in the user area and the OBKeys (OBK area)
// * by 16 bits or 32 bits (OTP and flash high-cycle data area).
// 8-KB sector erase, bank erase and dual-bank mass erase.

// Up to 8 sectors per each bank of the user main memory can be configured (via the FLASH_EDATA1R_PRG,
// resp. FLASH_EDATA2R_PRG registers) to support high cycling capability (100 K cycles) for data.
// When configured like this, this area is protected by a robust 6-bit ECC,
// enabling a 16-bit read and write granularity, at the expense of having sector size shrunk to 6 KB
// (max 8 * 6 = 48 KB of the high-cycling data memory per bank, 96 KB in total).
// See RM0481 7.3.10 Flash high-cycle data for more details.

// Note that DS14539 5.3.10 Memory characteristics Table 51. Flash memory endurance and data retention
// states the minial endurance of the flash memory is 10 K cycles,
// while a region with the high cycling capability enabled has a minial endurance of 100 K cycles.

// Note that the datasheet and the reference manual use the terms sector and page interchangeably.

// Apart from the 512-KB user main memory, the MCU also has:
// * 128 KB of system memory (also split between the two banks, 64 KB per each bank, i.e., 8 sectors).
// * A set of nonvolatile option bytes (located within Bank 1) loaded at reset by the embedded flash memory
//   and accessible by the application software only through the AHB configuration register interface.
// * A 2-KB one-time-programmable (OTP) area (located within Bank 1)
//   that can be written only once by the application software.
// * A 2-KB read-only (RO) area (located within Bank 1).
//   It contains a unique device ID and product information.
// * Two memory sectors (2 x 8 KB) of secure key storage, OBKeys (OBK) (located within Bank 2).

// The whole non-volatile memory embeds the error correction code (ECC) feature supporting:
// * Single-error detection and correction (SEC)
// * Double-error detection (DED)
// * ECC fail address report
// using 9-bit ECC on 128-bit words (user main memory, system memory, OBKey),
// using 6-bit ECC on  16-bit words (the configurable high-cycle data area of the user main memory, OTP, and RO).

// The embedded flash memory interface supports a read in one bank while a write operation
// or an erase operation is executed in the other bank (RWW - read while write).
// It does not support write-while-write, nor read-while-read.
// Same is valid for the high-cycle data area, system flash libraries, or the OBK (located on Bank2).

// The flash memory is mapped to (the underlying banks can be swapped using the SWAP_BANK bit
// of the FLASH_OPTCR register, which is loaded from the corresponding user nonvolatile option byte flag):
//   User main memory
//
//     Bank1 - 0x0800_0000 ... 0x0800_1FFF - Sector  0 (sector size 0x2000 = 8 KB)
//     Bank1 - 0x0800_2000 ... 0x0800_3FFF - Sector  2 (sector size 0x2000 = 8 KB)
//     Bank1 -             ...
//     Bank1 - 0x0803_E000 ... 0x0803_FFFF - Sector 31 (sector size 0x2000 = 8 KB)
//
//     Bank2 - 0x0804_0000 ... 0x0804_1FFF - Sector  0 (sector size 0x2000 = 8 KB)
//     Bank2 - 0x0804_2000 ... 0x0804_3FFF - Sector  2 (sector size 0x2000 = 8 KB)
//     Bank2 -             ...
//     Bank2 - 0x0807_E000 ... 0x0807_FFFF - Sector 31 (sector size 0x2000 = 8 KB)

// When the high-cycling data area of the user main memory is enabled
// (enabling/disabling of this area and the number of sectors is configured independently for each bank),
// up to 8 last sectors (each shrunk to 6 KB) are mapped to 0x0900_0000 - 0x0900_BFFF (bank 1, up to 48 KB)
//                                                          0x0900_C000 - 0x0901_7FFF (bank 2, up to 48 KB)
// See RM0481 7.3.10 Flash high-cycle data for more details
// (especially Figure 28. Flash high-cycle data memory map on 256-Kbyte devices).

void flash_erase_sector(uint8_t sector);

void flash_write(uint32_t addr, uint8_t *data, size_t size);

static_assert(FLASH_BASE == 0x08000000UL, "FLASH_BASE == 0x08000000UL");
static_assert(FLASH_EDATA_BASE == 0x09000000UL, "FLASH_EDATA_BASE == 0x09000000UL");

#endif // LIONKEY_STM32H33_FLASH_H
