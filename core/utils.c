#include "utils.h"

#if LIONKEY_DEBUG_LEVEL > 0

void dump_hex(const uint8_t *buf, size_t size) {
	debug_log("hex(%" PRIsz "): ", size);
	while (size--) {
		debug_log("%02" wPRIx8, *buf++);
	}
	debug_log(nl);
}

#endif
