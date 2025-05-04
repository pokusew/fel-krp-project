#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap_parse.h>
}
namespace {

class CtapParseGetAssertionTest : public testing::Test {
protected:
	CborParser parser{};
	CborValue it{};
	CTAP_getAssertion mc{};
	uint8_t status{};

	void test_ctap_parse_get_assertion(const uint8_t *data, size_t data_size) {
		status = ctap_init_cbor_parser(data, data_size, &parser, &it);
		if (status != CTAP2_OK) {
			return;
		}
		status = ctap_parse_get_assertion(&it, &mc);
	}

};


TEST_F(CtapParseGetAssertionTest, InvalidCbor) {
	auto params = hex::bytes<"ff">();
	test_ctap_parse_get_assertion(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_ERR_INVALID_CBOR);
}

TEST_F(CtapParseGetAssertionTest, MinimalWithPinUvAuthParam) {
	auto params = hex::bytes<
		// {
		//     1: "webauthn.io",
		//     2: h'5fcd421efacfd12841abc866ad829762add7865473973d7c00044b0fc6f07105',
		//     6: h'28f908390b81c3081dd57883c6072382',
		//     7: 1,
		// }
		"a4016b776562617574686e2e696f0258205fcd421efacfd12841abc866ad829762add7865473973d7c00044b0fc6f07105065028f908390b81c3081dd57883c60723820701"
	>();
	test_ctap_parse_get_assertion(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_getAssertion_rpId) |
		ctap_param_to_mask(CTAP_getAssertion_clientDataHash) |
		ctap_param_to_mask(CTAP_getAssertion_pinUvAuthParam) |
		ctap_param_to_mask(CTAP_getAssertion_pinUvAuthProtocol);
	EXPECT_EQ(mc.common.present, expected_present);

	auto expected_clientDataHash = hex::bytes<
		"5fcd421efacfd12841abc866ad829762add7865473973d7c00044b0fc6f07105"
	>();
	const uint8_t expected_rpId[] = "webauthn.io";
	auto expected_pinUvAuthParam = hex::bytes<
		"28f908390b81c3081dd57883c6072382"
	>();

	EXPECT_EQ(mc.common.clientDataHash.size, expected_clientDataHash.size());
	EXPECT_SAME_BYTES_S(mc.common.clientDataHash.size, mc.common.clientDataHash.data, expected_clientDataHash.data());

	EXPECT_EQ(mc.common.rpId.size, sizeof(expected_rpId) - 1);
	EXPECT_SAME_BYTES_S(mc.common.rpId.size, mc.common.rpId.data, expected_rpId);

	EXPECT_EQ(mc.common.pinUvAuthParam.size, expected_pinUvAuthParam.size());
	EXPECT_SAME_BYTES_S(mc.common.pinUvAuthParam.size, mc.common.pinUvAuthParam.data, expected_pinUvAuthParam.data());

	EXPECT_EQ(mc.common.pinUvAuthProtocol, 1);
}

TEST_F(CtapParseGetAssertionTest, SilentAuthnetication) {
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
	test_ctap_parse_get_assertion(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_getAssertion_rpId) |
		ctap_param_to_mask(CTAP_getAssertion_clientDataHash) |
		ctap_param_to_mask(CTAP_getAssertion_allowList) |
		ctap_param_to_mask(CTAP_getAssertion_options);
	EXPECT_EQ(mc.common.present, expected_present);

	auto expected_clientDataHash = hex::bytes<
		"76bb98f91bdc9c18a22c5db9e901cc278d27aa1d355fffcf4c3521392e15a1f1"
	>();
	const uint8_t expected_rpId[] = "webauthn.io";

	EXPECT_EQ(mc.common.clientDataHash.size, expected_clientDataHash.size());
	EXPECT_SAME_BYTES_S(mc.common.clientDataHash.size, mc.common.clientDataHash.data, expected_clientDataHash.data());

	EXPECT_EQ(mc.common.rpId.size, sizeof(expected_rpId) - 1);
	EXPECT_SAME_BYTES_S(mc.common.rpId.size, mc.common.rpId.data, expected_rpId);

	EXPECT_EQ(mc.common.options.present, CTAP_ma_ga_option_up);
	EXPECT_EQ(mc.common.options.values, 0u);
}

} // namespace
