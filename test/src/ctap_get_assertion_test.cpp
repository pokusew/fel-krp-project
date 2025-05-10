#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
}
namespace {

#define EXPECT_ERROR_RESPONSE(expected_status) \
    EXPECT_EQ(status, expected_status); \
    EXPECT_EQ(response.length, 0)

class CtapGetAssertionTest : public testing::Test {
protected:
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(sizeof(ctap_response_buffer), ctap_response_buffer);
	ctap_response_t &response = ctap.response;
	uint8_t status{};

	CtapGetAssertionTest() {

		// reset the consistent pseudo random number generator between tests
		// This is needed because the generator is global and multiple test cases
		// run sequentially (in one executable), each affecting the generator state.
		// We plan to improve the API to remove the global state and switch to an instance-based (context) API.
		ctap_rng_reset(0);

		ctap_init(&ctap);

	}

	template<size_t N>
	void test_ctap_get_assertion(const std::array<uint8_t, N> &params) {
		status = ctap_request(
			&ctap,
			CTAP_CMD_GET_ASSERTION,
			N,
			params.data()
		);
	}

};

TEST_F(CtapGetAssertionTest, WebauthnIoTest) {
	auto params = hex::bytes<
		// {
		//     1: "webauthn.io",
		//     2: h'76bb98f91bdc9c18a22c5db9e901cc278d27aa1d355fffcf4c3521392e15a1f1',
		//     3: [
		//         {
		//             "id": h'01263b6ab7f7d12c726023ac617740ef71ca6a026fe200bdf0bb0e6c8b8cf18a221e676c0770aaad9559537dfe78ed5a50997584ab7591a564c15a3f2b7c06d75c',
		//             "type": "public-key",
		//         },
		//         {
		//             "id": h'013ee311235b0fae88b3932efa7a667a0781dc98cb6f4c4788d7d6b46299a706add9023222ac1036ab943948844e92b293f97beb',
		//             "type": "public-key",
		//         },
		//     ],
		//     5: {"up": false},
		// }
		"a4016b776562617574686e2e696f02582076bb98f91bdc9c18a22c5db9e901cc278d27aa1d355fffcf4c3521392e15a1f10382a2626964584101263b6ab7f7d12c726023ac617740ef71ca6a026fe200bdf0bb0e6c8b8cf18a221e676c0770aaad9559537dfe78ed5a50997584ab7591a564c15a3f2b7c06d75c64747970656a7075626c69632d6b6579a26269645834013ee311235b0fae88b3932efa7a667a0781dc98cb6f4c4788d7d6b46299a706add9023222ac1036ab943948844e92b293f97beb64747970656a7075626c69632d6b657905a1627570f4"
	>();
	test_ctap_get_assertion(params);
	EXPECT_EQ(status, CTAP2_ERR_NO_CREDENTIALS);
}

} // namespace
