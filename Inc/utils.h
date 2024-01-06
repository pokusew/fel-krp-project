#ifndef POKUSEW_UTILS_H
#define POKUSEW_UTILS_H

#include <unistd.h>
#include <stdio.h>

#include "terminal.h"

// PRI*8 does not work correctly with -specs=nano.specs (which is currently needed because of salty)
// see https://answers.launchpad.net/gcc-arm-embedded/+question/665299
// see https://sourceware.org/legacy-ml/newlib/2016/msg00000.html
// for more info about -specs=nano.specs see https://metebalci.com/blog/demystifying-arm-gnu-toolchain-specs-nano-and-nosys/
// we could probably change salty build to not depend on nano libc and the full libc, see https://github.com/rust-lang/compiler-builtins/issues/353#issuecomment-698038631
#include <inttypes.h>
#define wPRId8 PRId16
#define wPRIi8 PRIi16
#define wPRIo8 PRIo16
#define wPRIu8 PRIu16
#define wPRIx8 PRIx16
#define wPRIX8 PRIX16

#ifndef nl
#define nl "\r\n"
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_of_3(a, b, c) min(min(a, b), (c))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define max_of_3(a, b, c) max(max(a, b), (c))
#define is_in_range_incl(value, min_incl, max_incl) ((min_incl) <= (value) && (value) <= (max_incl))
#define is_not_in_range_incl(value, min_incl, max_incl) ((value) < (min_incl) || (max_incl) < (value))
#define pow2(y) (1u << (y))

// macro(...) fn(other_arg, __VA_ARGS__)
// see https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c
// see https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html

#define POKUSEW_DEBUG_LEVEL 3

#if POKUSEW_DEBUG_LEVEL > 2
#define if_debug(code) (code)
#define debug_log(...) fprintf(stdout, __VA_ARGS__)
#define debug_log_str(line) write(STDERR_FILENO, (line), sizeof((line)))
#else
#define if_debug(code) ((void) 0)
#define debug_log(...) ((void) 0)
#define debug_log_str(line) ((void) 0)
// defining NDEBUG removes asserts
#define NDEBUG
#endif

#if POKUSEW_DEBUG_LEVEL > 1
#define info_log(...) fprintf(stdout, __VA_ARGS__)
#define info_log_str(line) write(STDERR_FILENO, (line), sizeof((line)))
#else
#define info_log(...) ((void) 0)
#define info_log_str(line) ((void) 0)
#endif

#if POKUSEW_DEBUG_LEVEL > 0
#define error_log(...) fprintf(stdout, __VA_ARGS__)
#define error_log_str(line) write(STDERR_FILENO, (line), sizeof((line)))
#else
#define error_log(...) ((void) 0)
#define error_log_str(line) ((void) 0)
#endif

#include <assert.h>

#define write_str(line) write(STDOUT_FILENO, (line), sizeof((line)));

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
