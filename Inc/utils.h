#ifndef POKUSEW_UTILS_H
#define POKUSEW_UTILS_H

#include <unistd.h>
#include <stdio.h>

#ifndef nl
#define nl "\r\n"
#endif

#define num_min(a, b) ((a) < (b) ? (a) : (b))
#define num_min_of_3(a, b, c) min(min(a, b), (c))
#define num_max(a, b) ((a) > (b) ? (a) : (b))
#define num_max_of_3(a, b, c) max(max(a, b), (c))
#define is_in_range_incl(value, min_incl, max_incl) ((min_incl) <= (value) && (value) <= (max_incl))
#define is_not_in_range_incl(value, min_incl, max_incl) ((value) < (min_incl) || (max_incl) < (value))
#define pow2(y) (1u << (y))

#define DEBUG 1

#if DEBUG != 1
// defining NDEBUG removes asserts
#define NDEBUG
#define debug(code) ((void) 0)
#define debug_printf(...) ((void) 0)
#define debug_print(line) ((void) 0)
#else
#define debug(code) (code)
// https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c
// https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
// note: it may be useful to use stderr instead of stdout
#define debug_printf(...) fprintf(stdout, __VA_ARGS__)
#define debug_print(line) write(STDERR_FILENO, (line), sizeof((line)))
#endif

#include <assert.h>

#define print(line) write(STDOUT_FILENO, (line), sizeof((line)));

#define print_error(line) write(STDERR_FILENO, (line), sizeof((line)));

#include <stdint.h>

#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)
#define DEBUG_BYTES(value) (debug_bytes((unsigned char *) &(value), sizeof(value)))
#define PRINT_BYTES(value) (print_bytes((unsigned char *) &(value), sizeof(value)))

void debug_sizeof();

void print_byte_as_bits(unsigned char value);

void convert_to_bits_string(unsigned int value, unsigned char *str, int num_bits);

void debug_bytes(const unsigned char *ptr, int size);

void print_bytes(const unsigned char *ptr, int size);

#endif // POKUSEW_UTILS_H
