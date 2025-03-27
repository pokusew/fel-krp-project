#include "utils.h"

#if LIONKEY_DEBUG_LEVEL > 0

void dump_hex(const uint8_t *buf, size_t size) {
	// TODO: arm-none-eabi does not support %zu?
	//       see https://stackoverflow.com/questions/76837281/zu-format-specifier-with-c99-not-working
	debug_log("hex(%u): ", size);
	while (size--) {
		debug_log("%02" wPRIx8, *buf++);
	}
	debug_log(nl);
}

#endif
