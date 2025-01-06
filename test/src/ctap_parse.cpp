#include <gtest/gtest.h>
#include <cbor.h>

static uint8_t data[50];

#define CTAP1_ERR_OTHER                     0x7F

void dump_hex(const uint8_t *buf, size_t size) {
	printf("hex(%zu): ", size);
	while (size--) {
		printf("%02x ", *buf++);
	}
	printf("\n");
}


// static_assert(sizeof(CborError) == sizeof(uint8_t), "CborError must fit into uint8_t");


#define nl "\n"

#define cbor_encoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP1_ERR_OTHER;                          \
    }



#if LIONKEY_LOG & 0x1

void lionkey_cbor_error_log(CborError err, int line, const char *filename) {
	printf("CborError: 0x%x at %s:%d: %s" nl, err, filename, line, cbor_error_string(err));
}

#else
#define lionkey_cbor_error_log(err, line, filename) ((void) 0)
#endif


// 8. Message Encoding
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding

// https://datatracker.ietf.org/doc/html/rfc8949#name-cbor-data-models

// https://cbor.nemo157.com/

TEST(CtapParse, BasicAssertions) {

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

// a201010202
// {1: 1, 2: 2}
