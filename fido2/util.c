#include <stdint.h>
#include <stdio.h>
#include "utils.h"

void dump_hex(const uint8_t *buf, int size) {
	debug_log("hex(%d): ", size);
	while (size--) {
		printf("%02x ", *buf++);
	}
	printf(nl);
}
