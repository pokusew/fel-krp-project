#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap_parse.h>
}
namespace {

TEST(CtapParseClientPin, InvalidCbor) {
	auto request = hex::bytes<"ff">();
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_ERR_INVALID_CBOR);
}

// TODO: Consider not allowing CBOR messages that are NOT in the CTAP2 canonical CBOR encoding form.
// See 8. Message Encoding (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding)
TEST(CtapParseClientPin, RequestCborNotCanonical) {
	auto request = hex::bytes<"a2 02 02 01 01">();
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(cp.pinUvAuthProtocol, 1);
	EXPECT_EQ(cp.subCommand, CTAP_clientPIN_subCmd_getKeyAgreement);
	EXPECT_EQ(cp.keyAgreementPresent, false);
	EXPECT_EQ(cp.pinUvAuthParamPresent, false);
	EXPECT_EQ(cp.newPinEncSize, 0);
	EXPECT_EQ(cp.pinHashEncPresent, false);
	EXPECT_EQ(cp.permissionsPresent, false);
	EXPECT_EQ(cp.rpIdPresent, false);
}

TEST(CtapParseClientPin, GetKeyAgreement) {
	auto request = hex::bytes<"a2 01 01 02 02">();
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(cp.pinUvAuthProtocol, 1);
	EXPECT_EQ(cp.subCommand, CTAP_clientPIN_subCmd_getKeyAgreement);
	EXPECT_EQ(cp.keyAgreementPresent, false);
	EXPECT_EQ(cp.pinUvAuthParamPresent, false);
	EXPECT_EQ(cp.newPinEncSize, 0);
	EXPECT_EQ(cp.pinHashEncPresent, false);
	EXPECT_EQ(cp.permissionsPresent, false);
	EXPECT_EQ(cp.rpIdPresent, false);
}

TEST(CtapParseClientPin, GetPinToken) {
	auto request = hex::bytes<
		"a40101020503a5010203381820012158203909e389b545662bfbee67905dd432"
		"e701a1c146acab6a5b420b75dd35105e5d225820f0b7cb3ebf62594b9e8d9870"
		"b1a9154ab50cdd2c1e6e861490b82d92f09e198406504d727d4dc01404d7e959"
		"0de7f04d89ca"
	>();
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(cp.pinUvAuthProtocol, 1);
	EXPECT_EQ(cp.subCommand, CTAP_clientPIN_subCmd_getPinToken);
	EXPECT_EQ(cp.keyAgreementPresent, true);
	EXPECT_EQ(cp.keyAgreement.kty, 2);
	EXPECT_EQ(cp.keyAgreement.crv, 1);
	auto expected_x = hex::bytes<"3909e389b545662bfbee67905dd432e701a1c146acab6a5b420b75dd35105e5d">();
	auto expected_y = hex::bytes<"f0b7cb3ebf62594b9e8d9870b1a9154ab50cdd2c1e6e861490b82d92f09e1984">();
	EXPECT_SAME_BYTES(
		cp.keyAgreement.pubkey.x,
		expected_x.data()
	);
	EXPECT_SAME_BYTES(
		cp.keyAgreement.pubkey.y,
		expected_y.data()
	);
	EXPECT_EQ(cp.pinUvAuthParamPresent, false);
	EXPECT_EQ(cp.newPinEncSize, 0);
	EXPECT_EQ(cp.pinHashEncPresent, true);
	EXPECT_EQ(cp.permissionsPresent, false);
	EXPECT_EQ(cp.rpIdPresent, false);
}

} // namespace
