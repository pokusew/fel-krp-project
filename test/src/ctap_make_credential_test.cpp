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

class CtapMakeCredentialTest : public testing::Test {
protected:
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_state_t ctap{
		.response = {
			.data_max_size = sizeof(ctap_response_buffer),
			.data = ctap_response_buffer,
		},
	};
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

TEST_F(CtapMakeCredentialTest, WebauthnIoTest) {
	auto params = hex::bytes<
		// {
		//     1: h'fad4059e31ddef7c75449ee9d8b523977b30d161d089f2a0a20c806875edb1aa',
		//     2: {"id": "webauthn.io", "name": "webauthn.io"},
		//     3: {
		//         "id": h'776562617574686e696f2d74657374',
		//         "name": "test",
		//         "displayName": "test",
		//     },
		//     4: [
		//         {"alg": -8, "type": "public-key"},
		//         {"alg": -7, "type": "public-key"},
		//         {"alg": -257_1, "type": "public-key"},
		//     ],
		//     5: [
		//         {
		//             "id": h'6bc8d540bd105aec6ee56d7f488f0a8107d43fc81ac6106825e7d627ebd8c841',
		//             "type": "public-key",
		//         },
		//         {
		//             "id": h'87289a32d2a94127beffaad16c1b040b',
		//             "type": "public-key",
		//         },
		//         {
		//             "id": h'a300582ba270ad3f706caa4dd3d5faa3eeb9a359065b157a394129b4c458c00f51ea32de9a604502e0c559b8acd93e014c68ae3dd838d5f43f70d4031e02508f1f27d4bebfbf25e35973bdac887ab1',
		//             "type": "public-key",
		//         },
		//     ],
		//     6: {"credProtect": 2},
		//     7: {"rk": true},
		//     8: h'91964252f79f51be8200364abc0e4d3e',
		//     9: 1,
		// }
		"a9015820fad4059e31ddef7c75449ee9d8b523977b30d161d089f2a0a20c806875edb1aa02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644f776562617574686e696f2d74657374646e616d6564746573746b646973706c61794e616d6564746573740483a263616c672764747970656a7075626c69632d6b6579a263616c672664747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b65790583a262696458206bc8d540bd105aec6ee56d7f488f0a8107d43fc81ac6106825e7d627ebd8c84164747970656a7075626c69632d6b6579a26269645087289a32d2a94127beffaad16c1b040b64747970656a7075626c69632d6b6579a2626964584fa300582ba270ad3f706caa4dd3d5faa3eeb9a359065b157a394129b4c458c00f51ea32de9a604502e0c559b8acd93e014c68ae3dd838d5f43f70d4031e02508f1f27d4bebfbf25e35973bdac887ab164747970656a7075626c69632d6b657906a16b6372656450726f746563740207a162726bf5085091964252f79f51be8200364abc0e4d3e0901"
	>();
	test_ctap_make_credential(params);
	EXPECT_EQ(status, CTAP2_OK);
}

} // namespace
