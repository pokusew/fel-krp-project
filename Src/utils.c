#include "utils.h"

void debug_sizeof() {
	debug_printf(
		"sizeof(int)=%u" nl
		"sizeof(long)=%u" nl
		"sizeof(long int)=%u" nl
		"sizeof(long long)=%u" nl
		"sizeof(long long int)=%u" nl,
		sizeof(int),
		sizeof(long),
		sizeof(long int),
		sizeof(long long),
		sizeof(long long int)
	);
}

void print_byte_as_bits(unsigned char value) {

	for (int i = 7; 0 <= i; i--) {
		debug_printf("%c", (value & (1 << i)) ? '1' : '0'); // NOLINT(hicpp-signed-bitwise)
	}

}

void debug_bytes(const unsigned char *ptr, int size) {

	debug_printf("  bits in MSB: ");

	if (IS_BIG_ENDIAN) {
		for (int i = 0; i < size; i++) {
			debug_printf(" ");
			print_byte_as_bits(*(ptr + i));
		}
	} else {
		for (int i = size - 1; i >= 0; i--) {
			debug_printf(" ");
			print_byte_as_bits(*(ptr + i));
		}
	}
	debug_printf(nl);

}

void print_bytes(const unsigned char *ptr, int size) {

	printf("  bytes in %s: ", IS_BIG_ENDIAN ? "MSB" : "LSB");
	for (int i = 0; i < size; i++) {
		printf(" 0x%02x", *(ptr + i));
	}
	printf(nl);

}

// str must be at least of size num_bits + 1
void convert_to_bits_string(unsigned int value, unsigned char *str, int num_bits) {

	str += num_bits;
	*str = '\0';

	unsigned char zero = '0';

	for (int i = num_bits; 0 <= i; i--) {
		*(--str) = zero + (value & 1);
		value >>= 1;
	}

}
