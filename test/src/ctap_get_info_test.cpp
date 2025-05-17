#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
#include <ctap_test.h>
}
namespace {

#define EXPECT_ERROR_RESPONSE(expected_status) \
	EXPECT_EQ(status, expected_status); \
	EXPECT_EQ(response.length, 0)

#define EXPECT_SUCCESS_RESPONSE() \
	EXPECT_EQ(status, CTAP2_OK); \
	if (status == CTAP2_OK) { \
		EXPECT_TRUE(test_validate_cbor(response.data, response.length)); \
	} \
	((void) 0)

class CtapGetInfoTest : public testing::Test {
protected:
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(&crypto);
	ctap_response_t response{
		.data_max_size = sizeof(ctap_response_buffer),
		.data = ctap_response_buffer,
	};
	uint8_t status{};

	CtapGetInfoTest() {
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	template<size_t N>
	void test_ctap_get_info(const std::array<uint8_t, N> &params) {
		status = ctap_request(
			&ctap,
			CTAP_CMD_GET_INFO,
			N,
			params.data(),
			&response
		);
	}

};

TEST_F(CtapGetInfoTest, ReturnsCannonicalCbor) {
	auto params = hex::bytes<"">();
	test_ctap_get_info(params);
	EXPECT_SUCCESS_RESPONSE();
}

} // namespace
