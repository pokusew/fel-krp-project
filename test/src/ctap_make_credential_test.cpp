#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
#include <utils.h>
}
namespace {

#define EXPECT_ERROR_RESPONSE(expected_status) \
	EXPECT_EQ(status, expected_status); \
	EXPECT_EQ(response.length, 0)

#define EXPECT_SUCCESS_EMPTY_RESPONSE() \
	EXPECT_EQ(status, CTAP2_OK); \
	EXPECT_EQ(response.length, 0)

class CtapMakeCredentialTest : public testing::Test {
protected:
	ctap_state_t ctap{};
	ctap_response_t &response = ctap.response;
	uint8_t status{};

	CtapMakeCredentialTest() {

		// reset the consistent pseudo random number generator between tests
		// This is needed because the generator is global and multiple test cases
		// run sequentially (in one executable), each affecting the generator state.
		// We plan to improve the API to remove the global state and switch to an instance-based (context) API.
		ctap_rng_reset(0);

		ctap_init(&ctap);

	}

	template<size_t N>
	void test_ctap_make_credential(const std::array<uint8_t, N> &params) {
		status = ctap_request(
			&ctap,
			CTAP_CMD_MAKE_CREDENTIAL,
			N,
			params.data()
		);
	}

};

TEST_F(CtapMakeCredentialTest, ZeroLengthPinUvAuthParam) {
	auto params = hex::bytes<
		// {
		//     1: h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		//     2: {"id": ".dummy"},
		//     3: {"id": h'01', "name": "dummy"},
		//     4: [{"alg": -7, "type": "public-key"}],
		//     8: h'',
		//     9: 1,
		// }
		"a6015820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85502a1626964662e64756d6d7903a26269644101646e616d656564756d6d790481a263616c672664747970656a7075626c69632d6b657908400901"
	>();
	test_ctap_make_credential(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_NOT_SET);
}

TEST_F(CtapMakeCredentialTest, PinUvAuthParamPresentButPinUvAuthProtocolAbsent) {
	auto params = hex::bytes<
		// {
		//     1: h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		//     2: {"id": ".dummy"},
		//     3: {"id": h'01', "name": "dummy"},
		//     4: [{"alg": -7, "type": "public-key"}],
		//     8: h'91964252f79f51be8200364abc0e4d3e',
		// }
		"a5015820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85502a1626964662e64756d6d7903a26269644101646e616d656564756d6d790481a263616c672664747970656a7075626c69632d6b6579085091964252f79f51be8200364abc0e4d3e"
	>();
	test_ctap_make_credential(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_MISSING_PARAMETER);
}

TEST_F(CtapMakeCredentialTest, UnsupportedPinUvAuthProtocol) {
	auto params = hex::bytes<
		// {
		//     1: h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		//     2: {"id": ".dummy"},
		//     3: {"id": h'01', "name": "dummy"},
		//     4: [{"alg": -7, "type": "public-key"}],
		//     8: h'91964252f79f51be8200364abc0e4d3e',
		//     9: 3,
		// }
		"a6015820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85502a1626964662e64756d6d7903a26269644101646e616d656564756d6d790481a263616c672664747970656a7075626c69632d6b6579085091964252f79f51be8200364abc0e4d3e0903"
	>();
	test_ctap_make_credential(params);
	EXPECT_ERROR_RESPONSE(CTAP1_ERR_INVALID_PARAMETER);
}

} // namespace
