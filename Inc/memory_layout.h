#ifndef POKUSEW_MEMORY_LAYOUT_H
#define POKUSEW_MEMORY_LAYOUT_H

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

#define STATE2_SECTOR 10
#define STATE1_SECTOR 9

#define COUNTER_COUNTS_PER_DATA_SECTOR (SECTOR_128KB_SIZE / 4)
#define COUNTER_DATA_SECTOR 8
#define COUNTER_NUM_ERASES_SECTOR 7

#include "assert.h"
static_assert(sizeof(AuthenticatorState) <= (128 * 1024), "AuthenticatorState does not fit into 128 KB");

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES        10
#define RK_START_PAGE_INCL  (PAGES - 14)
#define RK_END_PAGE_EXCL    (PAGES - 14 + RK_NUM_PAGES) // not included


#endif // POKUSEW_MEMORY_LAYOUT_H
