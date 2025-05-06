#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap_parse.h>
}
namespace {

class CtapParseCredentialManagementTest : public testing::Test {
protected:
	CborParser parser{};
	CborValue it{};
	CTAP_credentialManagement cm{};
	uint8_t status{};

	void test_ctap_parse_credential_management(const uint8_t *data, size_t data_size) {
		status = ctap_init_cbor_parser(data, data_size, &parser, &it);
		if (status != CTAP2_OK) {
			return;
		}
		status = ctap_parse_credential_management(&it, &cm);
	}

};


TEST_F(CtapParseCredentialManagementTest, InvalidCbor) {
	auto params = hex::bytes<"ff">();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_ERR_INVALID_CBOR);
}

TEST_F(CtapParseCredentialManagementTest, GetCredsMetadata) {
	auto params = hex::bytes<
		// {
		//     1: 1,
		//     3: 1,
		//     4: h'0a967ca521fe3790384697f3777e7c9c',
		// }
		"a30101030104500a967ca521fe3790384697f3777e7c9c"
	>();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthParam);
	EXPECT_EQ(cm.present, expected_present);

	auto expected_pinUvAuthParam = hex::bytes<
		"0a967ca521fe3790384697f3777e7c9c"
	>();

	EXPECT_EQ(cm.subCommand, CTAP_credentialManagement_subCmd_getCredsMetadata);
	EXPECT_EQ(cm.pinUvAuthProtocol, 1);
	EXPECT_EQ(cm.pinUvAuthParam.size, expected_pinUvAuthParam.size());
	EXPECT_SAME_BYTES_S(cm.pinUvAuthParam.size, cm.pinUvAuthParam.data, expected_pinUvAuthParam.data());
}

TEST_F(CtapParseCredentialManagementTest, EnumerateRPsBegin) {
	auto params = hex::bytes<
		// {
		//     1: 2,
		//     3: 1,
		//     4: h'62ee5f270547ffa1d674ef25cc1d3d8f',
		// }
		"a301020301045062ee5f270547ffa1d674ef25cc1d3d8f"
	>();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthParam);
	EXPECT_EQ(cm.present, expected_present);

	auto expected_pinUvAuthParam = hex::bytes<
		"62ee5f270547ffa1d674ef25cc1d3d8f"
	>();

	EXPECT_EQ(cm.subCommand, CTAP_credentialManagement_subCmd_enumerateRPsBegin);
	EXPECT_EQ(cm.pinUvAuthProtocol, 1);
	EXPECT_EQ(cm.pinUvAuthParam.size, expected_pinUvAuthParam.size());
	EXPECT_SAME_BYTES_S(cm.pinUvAuthParam.size, cm.pinUvAuthParam.data, expected_pinUvAuthParam.data());
}

TEST_F(CtapParseCredentialManagementTest, EnumerateCredentialsBegin) {
	auto params = hex::bytes<
		// {
		//     1: 4,
		//     2: {
		//         1: h'74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0',
		//     },
		//     3: 1,
		//     4: h'9be8ef799e43da8d50a3ceab2cadc8c5',
		// }
		"a4010402a101582074a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0030104509be8ef799e43da8d50a3ceab2cadc8c5"
	>();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_rpIDHash) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthParam);
	EXPECT_EQ(cm.present, expected_present);

	EXPECT_EQ(cm.subCommand, CTAP_credentialManagement_subCmd_enumerateCredentialsBegin);

	EXPECT_EQ(cm.subCommandParams.raw_size, 36);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.raw_size, cm.subCommandParams.raw, &params[4]);
	constexpr uint32_t expected_subCommandParams_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_rpIDHash);
	EXPECT_EQ(cm.subCommandParams.present, expected_subCommandParams_present);
	EXPECT_EQ(cm.subCommandParams.rpIDHash.size, 32);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.rpIDHash.size, cm.subCommandParams.rpIDHash.data, &params[8]);

	EXPECT_EQ(cm.pinUvAuthProtocol, 1);
	EXPECT_EQ(cm.pinUvAuthParam.size, 16);
	EXPECT_SAME_BYTES_S(cm.pinUvAuthParam.size, cm.pinUvAuthParam.data, &params[44]);
}

TEST_F(CtapParseCredentialManagementTest, DeleteCredential) {
	auto params = hex::bytes<
		// {
		//     1: 6,
		//     2: {
		//         2: {
		//             "id": h'011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77',
		//             "type": "public-key",
		//         },
		//     },
		//     3: 1,
		//     4: h'6f1257e16d4f324f940dedb3694d52ab',
		// }
		"a4010602a102a26269645880011a04a37f41ff124f4298cb73f6f954b3d4ecb51e827f56637b60a7aa7face1f0e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae7764747970656a7075626c69632d6b6579030104506f1257e16d4f324f940dedb3694d52ab"
	>();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_rpIDHash) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthParam);
	EXPECT_EQ(cm.present, expected_present);

	EXPECT_EQ(cm.subCommand, CTAP_credentialManagement_subCmd_deleteCredential);

	EXPECT_EQ(cm.subCommandParams.raw_size, 152);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.raw_size, cm.subCommandParams.raw, &params[4]);
	constexpr uint32_t expected_subCommandParams_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_credentialID);
	EXPECT_EQ(cm.subCommandParams.present, expected_subCommandParams_present);
	EXPECT_EQ(cm.subCommandParams.credentialID.type, CTAP_pubKeyCredType_public_key);
	EXPECT_EQ(cm.subCommandParams.credentialID.id.size, 128);
	EXPECT_SAME_BYTES_S(
		cm.subCommandParams.credentialID.id.size, cm.subCommandParams.credentialID.id.data, &params[12]
	);

	EXPECT_EQ(cm.pinUvAuthProtocol, 1);
	EXPECT_EQ(cm.pinUvAuthParam.size, 16);
	EXPECT_SAME_BYTES_S(cm.pinUvAuthParam.size, cm.pinUvAuthParam.data, &params[160]);
}

TEST_F(CtapParseCredentialManagementTest, UpdateUserInformation) {
	auto params = hex::bytes<
		// {
		//     1: 7,
		//     2: {
		//         2: {
		//             "id": h'01e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77c78abf7d00c51fc7184418ec5f66f19c6ac0d8304d4f3a10c0d67b61782ce205',
		//             "type": "public-key",
		//         },
		//         3: {
		//             "id": h'776562617574686e696f2d706f6b757365772d68352d31',
		//             "name": "pokusew-h5-1-USERNAME",
		//             "displayName": "pokusew-h5-1-NAME",
		//         },
		//     },
		//     3: 1,
		//     4: h'0708b13123dd0cdf8ceef1c4ce9fd707',
		// }
		"a4010702a202a2626964588001e4384d663a1eb750aa6738e0eeb6668c478307c364c30cea6048ee6683ab27735c9418d7491f308121cd0dd94671b19a722a25118c811ad42d34aa68ac767281878b2b5a2f26bedeecbf38adb0dfa30d29c86fdf7806b8840a72a22a4cae77c78abf7d00c51fc7184418ec5f66f19c6ac0d8304d4f3a10c0d67b61782ce20564747970656a7075626c69632d6b657903a362696457776562617574686e696f2d706f6b757365772d68352d31646e616d6575706f6b757365772d68352d312d555345524e414d456b646973706c61794e616d6571706f6b757365772d68352d312d4e414d45030104500708b13123dd0cdf8ceef1c4ce9fd707"
	>();
	test_ctap_parse_credential_management(params.data(), params.size());
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommand) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams) |
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_rpIDHash) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_credentialManagement_pinUvAuthParam);
	EXPECT_EQ(cm.present, expected_present);

	EXPECT_EQ(cm.subCommand, CTAP_credentialManagement_subCmd_updateUserInformation);

	EXPECT_EQ(cm.subCommandParams.raw_size, 238);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.raw_size, cm.subCommandParams.raw, &params[4]);
	constexpr uint32_t expected_subCommandParams_present =
		ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_credentialID)
		| ctap_param_to_mask(CTAP_credentialManagement_subCommandParams_user);
	EXPECT_EQ(cm.subCommandParams.present, expected_subCommandParams_present);
	EXPECT_EQ(cm.subCommandParams.credentialID.type, CTAP_pubKeyCredType_public_key);
	EXPECT_EQ(cm.subCommandParams.credentialID.id.size, 128);
	EXPECT_SAME_BYTES_S(
		cm.subCommandParams.credentialID.id.size, cm.subCommandParams.credentialID.id.data, &params[12]
	);
	constexpr uint32_t expected_subCommandParams_user_present =
		ctap_param_to_mask(CTAP_userEntity_id)
		| ctap_param_to_mask(CTAP_userEntity_name)
		| ctap_param_to_mask(CTAP_userEntity_displayName);
	EXPECT_EQ(cm.subCommandParams.user.present, expected_subCommandParams_user_present);
	EXPECT_EQ(cm.subCommandParams.user.id.size, 23);
	EXPECT_EQ(cm.subCommandParams.user.name.size, 21);
	EXPECT_EQ(cm.subCommandParams.user.displayName.size, 17);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.user.id.size, cm.subCommandParams.user.id.data, &params[162]);
	EXPECT_SAME_BYTES_S(cm.subCommandParams.user.name.size, cm.subCommandParams.user.name.data, &params[191]);
	EXPECT_SAME_BYTES_S(
		cm.subCommandParams.user.displayName.size, cm.subCommandParams.user.displayName.data, &params[225]
	);

	EXPECT_EQ(cm.pinUvAuthProtocol, 1);
	EXPECT_EQ(cm.pinUvAuthParam.size, 16);
	EXPECT_SAME_BYTES_S(cm.pinUvAuthParam.size, cm.pinUvAuthParam.data, &params[246]);
}

} // namespace
