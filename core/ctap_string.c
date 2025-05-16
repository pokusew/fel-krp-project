#include "ctap_string.h"
#include "utils.h"
#include <string.h> // memcmp()

bool ctap_string_matches(const ctap_string_t *a, const ctap_string_t *b) {
	const size_t size = a->size;
	if (size != b->size) {
		return false;
	}
	return memcmp(a->data, b->data, size) == 0;
}

bool ctap_maybe_truncate_string(
	const ctap_string_t *const input_str,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	size_t *const stored_size
) {

	// see WebAuthn 6.4. String Handling (6.4.1.2. String Truncation by Authenticators)
	//   https://w3c.github.io/webauthn/#sctn-strings

	// no truncation needed
	if (input_str->size <= storage_buffer_size) {
		memcpy(storage_buffer, input_str->data, input_str->size);
		*stored_size = input_str->size;
		return false;
	}

	assert(input_str->size > storage_buffer_size);
	// TODO:
	//  The truncation SHOULD respect UTF-8 code point boundaries,
	//  and MAY respect grapheme cluster boundaries.
	//  The resulting truncated value MAY be shorter than the chosen size limit
	//  but MUST NOT be shorter than the longest prefix substring
	//  that satisfies the size limit and ends on a grapheme cluster boundary.
	memcpy(storage_buffer, input_str->data, storage_buffer_size);
	*stored_size = storage_buffer_size;
	return true;

}

bool ctap_maybe_truncate_rp_id(
	const ctap_string_t *const rp_id,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	size_t *const stored_size
) {

	// see 6.8.7. Truncation of relying party identifiers
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
	// see WebAuthn 6.4. String Handling (6.4.1.2. String Truncation by Authenticators)
	//   https://w3c.github.io/webauthn/#sctn-strings

	// If authenticators store relying party identifiers at all, they MUST store at least 32 bytes.
	assert(storage_buffer_size >= 32);

	if (rp_id->size <= storage_buffer_size) {
		memcpy(storage_buffer, rp_id->data, rp_id->size);
		*stored_size = rp_id->size;
		return false;
	}

	size_t used = 0;

	// [protocol]://[host]
	const uint8_t *colon_position = memchr(rp_id->data, ':', rp_id->size);
	if (colon_position != NULL) {
		assert(rp_id->data <= colon_position && colon_position < (rp_id->data + rp_id->size));
		const size_t protocol_len = colon_position - rp_id->data + 1; // + 1 for the colon itself
		// protocol strings are preserved if possible
		const size_t to_copy = protocol_len <= storage_buffer_size
			? protocol_len
			: storage_buffer_size;
		assert(to_copy <= storage_buffer_size);
		memcpy(storage_buffer, rp_id->data, to_copy);
		used += to_copy;
	}

	if (storage_buffer_size - used < 3) {
		*stored_size = used;
		return true;
	}

	// U+2026, horizontal ellipsis
	storage_buffer[used++] = 0xe2;
	storage_buffer[used++] = 0x80;
	storage_buffer[used++] = 0xa6;

	const size_t to_copy = storage_buffer_size - used;
	assert(used + to_copy == storage_buffer_size);
	memcpy(&storage_buffer[used], rp_id->data + rp_id->size - to_copy, to_copy);
	*stored_size = storage_buffer_size;
	return true;

}

bool ctap_store_arbitrary_length_string(
	const ctap_string_t *const input_str,
	ctap_string_t *const str,
	uint8_t *const storage_buffer,
	const size_t storage_buffer_size,
	ctap_truncate_str truncate_fn
) {

	assert(truncate_fn != NULL);

	str->data = storage_buffer;

	const bool was_truncated = truncate_fn(
		input_str,
		storage_buffer,
		storage_buffer_size,
		&str->size
	);

	assert(str->size <= storage_buffer_size);
	assert(str->size <= input_str->size);

	if (was_truncated) {
		debug_log(
			red("truncated string from %" PRIsz " bytes to %" PRIsz " bytes for storage (max %" PRIsz " bytes)") nl,
			input_str->size, str->size, storage_buffer_size
		);
	}

	return was_truncated;

}
