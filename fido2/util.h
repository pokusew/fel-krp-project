#ifndef FIDO2_UTIL_H
#define FIDO2_UTIL_H

#include <stdint.h>

void dump_hex(const uint8_t *buf, int size);

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#endif // FIDO2_UTIL_H
