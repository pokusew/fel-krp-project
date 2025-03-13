#ifndef POKUSEW_FLASH_H
#define POKUSEW_FLASH_H

// STM32F407IGH6 has 1024 KB of Flash memory
// mapped to memory address range 0x0800_0000 - 0x080F_FFFF
// see Section 4, Memory Mapping, in the STM32F407IG datasheet (DS8626)
// A main memory block divided into 12 sectors (with different sizes)
// - 4 sectors of  16 KB: sectors   0-3
// - 1 sector  of  64 KB: sector      4
// - 7 sectors of 128 KB: sectors: 5-11
// 4*16+64+7*128 = 1024

void flash_erase_sector(uint8_t sector);

void flash_write(uint32_t addr, uint8_t *data, size_t size);

#define SECTOR_128KB_SIZE (128 * 1024) // size in bytes

#define flash_128KB_sector_to_addr(sector) (0x08000000 + ((((sector) - 5) + 1) * (128 * 1024)))

#endif // POKUSEW_FLASH_H
