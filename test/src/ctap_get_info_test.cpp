#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
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
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(sizeof(ctap_response_buffer), ctap_response_buffer);
	ctap_response_t &response = ctap.response;
	uint8_t status{};

	CtapGetInfoTest() {

		// reset the consistent pseudo random number generator between tests
		// This is needed because the generator is global and multiple test cases
		// run sequentially (in one executable), each affecting the generator state.
		// We plan to improve the API to remove the global state and switch to an instance-based (context) API.
		ctap_rng_reset(0);

		ctap_init(&ctap);

	}

	template<size_t N>
	void test_ctap_get_info(const std::array<uint8_t, N> &params) {
		status = ctap_request(
			&ctap,
			CTAP_CMD_GET_INFO,
			N,
			params.data()
		);
	}

};

TEST_F(CtapGetInfoTest, ReturnsCannonicalCbor) {
	auto params = hex::bytes<"">();
	test_ctap_get_info(params);
	EXPECT_SUCCESS_RESPONSE();
}

} // namespace
