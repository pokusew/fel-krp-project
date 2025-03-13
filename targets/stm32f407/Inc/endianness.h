#ifndef POKUSEW_ENDIANNESS_H
#define POKUSEW_ENDIANNESS_H

#include <stdint.h>

#define ntohs(x)        __builtin_bswap16(x)
#define htons(x)        __builtin_bswap16(x)

#define ntohl(x)        __builtin_bswap32(x)
#define htonl(x)        __builtin_bswap32(x)

#endif // POKUSEW_ENDIANNESS_H
