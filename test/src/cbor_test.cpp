#include <gtest/gtest.h>
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

} // namespace
