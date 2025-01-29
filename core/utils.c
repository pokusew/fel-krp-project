#include "utils.h"

void dump_hex(const uint8_t *buf, size_t size) {
	printf("hex(%zu): ", size);
	while (size--) {
		printf("%02x ", *buf++);
	}
	printf("\n");
}
