#ifndef LIONKEY_CTAP_STRING_H
#define LIONKEY_CTAP_STRING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct ctap_string {
	size_t size;
	const uint8_t *data;
} ctap_string_t;

#define ctap_str(str) ((const ctap_string_t) {.size = sizeof((str)) - 1, .data = (const uint8_t *) (str)})
#define ctap_str_i(str) {.size = sizeof((str)) - 1, .data = (const uint8_t *) (str)}

bool ctap_string_matches(const ctap_string_t *a, const ctap_string_t *b);

typedef bool (*ctap_truncate_str)(
	const ctap_string_t *str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_maybe_truncate_string(
	const ctap_string_t *input_str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_maybe_truncate_rp_id(
	const ctap_string_t *rp_id,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	size_t *stored_size
);

bool ctap_store_arbitrary_length_string(
	const ctap_string_t *input_str,
	ctap_string_t *str,
	uint8_t *storage_buffer,
	size_t storage_buffer_size,
	ctap_truncate_str truncate_fn
);

#endif // LIONKEY_CTAP_STRING_H
