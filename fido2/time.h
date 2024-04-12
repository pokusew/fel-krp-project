#ifndef FIDO2_TIME_H
#define FIDO2_TIME_H

#include <stdint.h>

typedef uint32_t millis_t;

/**
 * Return a millisecond timestamp.
 */
uint32_t millis();

uint32_t timestamp_diff(uint32_t start);

#endif // FIDO2_TIME_H
