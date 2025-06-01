#ifndef LIONKEY_COMPILER_H
#define LIONKEY_COMPILER_H

// https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Type-Attributes.html
// https://gcc.gnu.org/onlinedocs/gcc-14.2.0/gcc/Attribute-Syntax.html

#define LION_ATTR_PACKED         __attribute__ ((packed))
#define LION_ATTR_ALWAYS_INLINE  __attribute__ ((always_inline))

// https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-aligned-variable-attribute
// The aligned attribute specifies a minimum alignment for the variable or structure field, measured in bytes.
// The num_bytes value must be an integer constant power of 2.
#define LION_ATTR_ALIGNED(num_bytes) __attribute__ ((aligned(num_bytes)))

#define lion_unused(x) ((void) (x))

// lion_static_assert_expr(expr, msg) is a static assert that can be used in an expression context
// (the standard static_assert is a statement and thus cannot be used in an expression)
// lion_static_assert_expr(expr, msg) is an expression that evaluates to value 1
#ifndef __cplusplus
// credits: https://stackoverflow.com/a/78596491
#define lion_static_assert_expr(expr, msg) \
	(!!sizeof(struct { static_assert((expr), msg); char c; }))
#else
// credits: https://stackoverflow.com/a/31311923
#define lion_static_assert_expr(expr, msg) \
	(([]{ static_assert((expr), msg); }), 1)
#endif

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
