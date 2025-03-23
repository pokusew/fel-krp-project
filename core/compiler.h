#ifndef LIONKEY_COMPILER_H
#define LIONKEY_COMPILER_H

// https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Type-Attributes.html
// https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Attribute-Syntax.html

#define LION_ATTR_PACKED         __attribute__ ((packed))
#define LION_ATTR_ALWAYS_INLINE  __attribute__ ((always_inline))

#define lion_bswap16(u16) (__builtin_bswap16(u16))
#define lion_bswap32(u32) (__builtin_bswap32(u32))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define LION_BYTE_ORDER LION_LITTLE_ENDIAN
#else
	#define LION_BYTE_ORDER LION_BIG_ENDIAN
#endif

#if (LION_BYTE_ORDER == LION_LITTLE_ENDIAN)

	#define lion_htons(u16)  (lion_bswap16(u16))
	#define lion_ntohs(u16)  (lion_bswap16(u16))

	#define lion_htonl(u32)  (lion_bswap32(u32))
	#define lion_ntohl(u32)  (lion_bswap32(u32))

	#define lion_htole16(u16) (u16)
	#define lion_le16toh(u16) (u16)

	#define lion_htole32(u32) (u32)
	#define lion_le32toh(u32) (u32)

#elif (LION_BYTE_ORDER == LION_BIG_ENDIAN)

	#define lion_htons(u16)  (u16)
	#define lion_ntohs(u16)  (u16)

	#define lion_htonl(u32)  (u32)
	#define lion_ntohl(u32)  (u32)

	#define lion_htole16(u16) (lion_bswap16(u16))
	#define lion_le16toh(u16) (lion_bswap16(u16))

	#define lion_htole32(u32) (lion_bswap32(u32))
	#define lion_le32toh(u32) (lion_bswap32(u32))

#else
	#error LION_BYTE_ORDER order is undefined
#endif

#endif // LIONKEY_COMPILER_H
