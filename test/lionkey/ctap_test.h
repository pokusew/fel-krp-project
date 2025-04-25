#ifndef LIONKEY_CTAP_TEST_H
#define LIONKEY_CTAP_TEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool test_validate_cbor(const uint8_t *data, size_t data_size);

#endif // LIONKEY_CTAP_TEST_H
