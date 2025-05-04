#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cbor.h>
namespace {

void dump_hex(const uint8_t *buf, size_t size) {
	printf("hex(%zu): ", size);
	while (size--) {
		printf("%02x ", *buf++);
	}
	printf("\n");
}

// CTAP2:
//   8. Message Encoding
//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding

// RFC 8949: Concise Binary Object Representation (CBOR)
// https://datatracker.ietf.org/doc/html/rfc8949

// CBOR Playground
// https://cbor.nemo157.com/

TEST(CborTest, EncodesTwoInts) {

	uint8_t data[50];

	CborEncoder encoder;
	CborError err;

	cbor_encoder_init(&encoder, data, sizeof(data), 0);

	err = cbor_encode_int(&encoder, 5);
	ASSERT_EQ(err, CborNoError);

	err = cbor_encode_int(&encoder, 5);
	// ASSERT_EQ(err, CborErrorOutOfMemory);
	ASSERT_EQ(err, CborNoError);

	size_t len = cbor_encoder_get_buffer_size(&encoder, data);
	ASSERT_EQ(len, 2);

	dump_hex(data, len);

}

// CTAP2 spec, Section 8. Message Encoding:
// Because some authenticators are memory constrained,
// the depth of nested CBOR structures used by all message encodings
// is limited to at most four (4) levels of any combination of CBOR maps
// and/or CBOR arrays.
// Authenticators MUST support at least 4 levels of CBOR nesting.
// Clients, platforms, and servers MUST NOT use more than 4 levels of CBOR nesting.
TEST(CborTest, MaxRecursionExceeded) {

	static_assert(CBOR_PARSER_MAX_RECURSIONS == 4);
	// {1: {2: {3: {4: {5: 0}}}}, -1: 99}
	auto data = hex::bytes<"a2 01 a1 02 a1 03 a1 04 a1 05 00 20 18 63">();

	CborParser parser;
	CborValue it;

	CborError err;

	err = cbor_parser_init(
		data.data(),
		data.size(),
		0,
		&parser,
		&it
	);
	ASSERT_EQ(err, CborNoError);

	ASSERT_EQ(cbor_value_is_map(&it), true);

	err = cbor_value_advance(&it);
	ASSERT_EQ(err, CborErrorNestingTooDeep);

}

TEST(CborTest, MaxRecursion) {

	static_assert(CBOR_PARSER_MAX_RECURSIONS == 4);
	// {1: {2: {3: {4: 0}}}, -1: 99}
	auto data = hex::bytes<"a2 01 a1 02 a1 03 a1 04 00 20 18 63">();

	CborParser parser;
	CborValue it;

	CborError err;

	err = cbor_parser_init(
		data.data(),
		data.size(),
		0,
		&parser,
		&it
	);
	ASSERT_EQ(err, CborNoError);

	ASSERT_EQ(cbor_value_is_map(&it), true);

	err = cbor_value_advance(&it);
	ASSERT_EQ(err, CborNoError);

}

TEST(CborTest, ParsesByteStringIndefiniteLengthTwoChunks) {

	// see RFC 8949, 3.2.3. Indefinite-Length Byte Strings and Text Strings
	//   https://datatracker.ietf.org/doc/html/rfc8949#section-3.2.3

	auto data = hex::bytes<
		// [(_ h'aabbccdd', h'eeff99'), 2]
		"82               " // array(2)
		"   5f            " //   bytes(*)
		"      44         " //     bytes(4)
		"         aabbccdd" //       "\xaa\xbb\xcc\xdd"
		"      43         " //     bytes(3)
		"         eeff99  " //       "\xee\xff\x99"
		"      ff         " //     break
		"   02            " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"aabbccddeeff99">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), false);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborErrorUnknownLength);
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, 4);
		EXPECT_SAME_BYTES_S(chunk_length, chunk, &expected_string[0]);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, 3);
		EXPECT_SAME_BYTES_S(chunk_length, chunk, &expected_string[4]);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

TEST(CborTest, ParsesByteStringIndefiniteLengthTwoChunksButOneWithZeroLength) {

	// see RFC 8949, 3.2.3. Indefinite-Length Byte Strings and Text Strings
	//   https://datatracker.ietf.org/doc/html/rfc8949#section-3.2.3

	auto data = hex::bytes<
		// [(_ h'', h'eeff99'), 2]
		"82             " // array(2)
		"   5f          " //   bytes(*)
		"      40       " //     bytes(0)
		"               " //       ""
		"      43       " //     bytes(3)
		"         eeff99" //       "\xee\xff\x99"
		"      ff       " //     break
		"   02          " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"eeff99">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), false);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborErrorUnknownLength);
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, 0);
		EXPECT_SAME_BYTES_S(chunk_length, chunk, &expected_string[0]);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, 3);
		EXPECT_SAME_BYTES_S(chunk_length, chunk, &expected_string[0]);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

TEST(CborTest, ParsesByteStringIndefiniteLengthOneChunk) {

	// see RFC 8949, 3.2.3. Indefinite-Length Byte Strings and Text Strings
	//   https://datatracker.ietf.org/doc/html/rfc8949#section-3.2.3

	auto data = hex::bytes<
		// [(_ h'aabbccdd'), 2]
		"82               " // array(2)
		"   5f            " //   bytes(*)
		"      44         " //     bytes(4)
		"         aabbccdd" //       "\xaa\xbb\xcc\xdd"
		"      ff         " //     break
		"   02            " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"aabbccdd">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), false);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborErrorUnknownLength);
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, 4);
		EXPECT_SAME_BYTES_S(chunk_length, chunk, &expected_string[0]);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

TEST(CborTest, ParsesByteStringIndefiniteLengthZeroChunks) {

	// see RFC 8949, 3.2.3. Indefinite-Length Byte Strings and Text Strings
	//   https://datatracker.ietf.org/doc/html/rfc8949#section-3.2.3

	auto data = hex::bytes<
		// [(_), 2]
		"82               " // array(2)
		"   5f            " //   bytes(*)
		"      ff         " //     break
		"   02            " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), false);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborErrorUnknownLength);
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

TEST(CborTest, ParsesByteStringDefiniteLength7) {

	auto data = hex::bytes<
		// [h'aabbccddeeff99', 2]
		"82                  " // array(2)
		"   47               " //   bytes(7)
		"      aabbccddeeff99" //     "\xaa\xbb\xcc\xdd\xee\xff\x99"
		"   02               " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"aabbccddeeff99">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), true);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	//    (TinyCBOR offers the same consistent API for both indefinite-length strings (i.e., chunked strings)
	//     and definite-length strings (which are not chunked, but TinyCBOR API treats them as single-chunk strings)
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, expected_string.size());
		EXPECT_SAME_BYTES_S(chunk_length, chunk, expected_string.data());

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

TEST(CborTest, ParsesByteStringDefiniteLength0) {

	auto data = hex::bytes<
		// [h'', 2]
		"82    " // array(2)
		"   40 " //   bytes(0)
		"      " //     ""
		"   02 " //   unsigned(2)
	>();
	auto expected_string = hex::bytes<"">();
	const uint64_t expected_value_after_string = 2;

	CborParser parser;
	CborValue it;
	CborValue it2;
	CborValue byte_string;
	size_t length;
	uint64_t value_after_string;

	ASSERT_EQ(
		cbor_parser_init(
			data.data(),
			data.size(),
			0,
			&parser,
			&it
		),
		CborNoError
	);

	ASSERT_EQ(cbor_value_is_array(&it), true);
	ASSERT_EQ(cbor_value_is_length_known(&it), true);
	ASSERT_EQ(cbor_value_get_array_length(&it, &length), CborNoError);
	ASSERT_EQ(length, 2);
	ASSERT_EQ(cbor_value_enter_container(&it, &it2), CborNoError);

	ASSERT_EQ(cbor_value_is_byte_string(&it2), true);
	ASSERT_EQ(cbor_value_is_length_known(&it2), true);

	ASSERT_EQ(cbor_value_get_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	ASSERT_EQ(cbor_value_calculate_string_length(&it2, &length), CborNoError);
	ASSERT_EQ(length, expected_string.size());
	byte_string = it2;

	// a) using the cbor_value_copy_byte_string() API
	{
		it2 = byte_string;
		uint8_t buffer[expected_string.size()];
		length = sizeof(buffer);
		ASSERT_EQ(cbor_value_copy_byte_string(&it2, buffer, &length, &it2), CborNoError);
		ASSERT_EQ(length, expected_string.size());
		EXPECT_SAME_BYTES_S(length, buffer, expected_string.data());

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}
	// b) using the cbor_value_get_text_string_chunk() API
	//    (TinyCBOR offers the same consistent API for both indefinite-length strings (i.e., chunked strings)
	//     and definite-length strings (which are not chunked, but TinyCBOR API treats them as single-chunk strings)
	{
		it2 = byte_string;
		const uint8_t *chunk;
		size_t chunk_length;

		ASSERT_EQ(cbor_value_begin_string_iteration(&it2), CborNoError);

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborNoError);
		ASSERT_NE(chunk, nullptr);
		ASSERT_EQ(chunk_length, expected_string.size());
		EXPECT_SAME_BYTES_S(chunk_length, chunk, expected_string.data());

		ASSERT_EQ(cbor_value_get_byte_string_chunk(&it2, &chunk, &chunk_length, &it2), CborErrorNoMoreStringChunks);

		ASSERT_EQ(cbor_value_finish_string_iteration(&it2), CborNoError);

		// check that the it2 (we passed it as the next pointer to the cbor_value_copy_byte_string())
		// now correctly points the item after the string
		ASSERT_EQ(cbor_value_is_unsigned_integer(&it2), true);
		ASSERT_EQ(cbor_value_get_uint64(&it2, &value_after_string), CborNoError);
		ASSERT_EQ(value_after_string, expected_value_after_string);
	}

}

} // namespace
