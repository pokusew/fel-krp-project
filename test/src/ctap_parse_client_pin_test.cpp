#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap_parse.h>
}
namespace {

uint8_t test_ctap_parse_client_pin(const uint8_t *data, size_t data_size, CTAP_clientPIN *cp) {
	CborParser parser;
	CborValue it;
	uint8_t ret;
	ctap_check(ctap_init_cbor_parser(data, data_size, &parser, &it));
	return ctap_parse_client_pin(&it, cp);
}

// TODO: Consider not allowing CBOR messages that are NOT in the CTAP2 canonical CBOR encoding form.
// See 8. Message Encoding (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding)
TEST(CtapParseClientPinTest, RequestCborNotCanonical) {
	auto request = hex::bytes<"a2 02 02 01 01">();
	CTAP_clientPIN cp;
	uint8_t status;
	status = test_ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_clientPIN_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_clientPIN_subCommand);
	EXPECT_EQ(cp.present, expected_present);
}

TEST(CtapParseClientPinTest, GetKeyAgreement) {
	auto request = hex::bytes<"a2 01 01 02 02">();
	CTAP_clientPIN cp;
	uint8_t status;
	status = test_ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_clientPIN_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_clientPIN_subCommand);
	EXPECT_EQ(cp.present, expected_present);
}

TEST(CtapParseClientPinTest, GetPinToken) {
	auto request = hex::bytes<
		// {
		//     1: 1,
		//     2: 5,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'3909e389b545662bfbee67905dd432e701a1c146acab6a5b420b75dd35105e5d',
		//         -3: h'f0b7cb3ebf62594b9e8d9870b1a9154ab50cdd2c1e6e861490b82d92f09e1984',
		//     },
		//     6: h'4d727d4dc01404d7e9590de7f04d89ca',
		// }
		"a4"
		"  01 01"
		"  02 05"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820"
		"          3909e389b545662bfbee67905dd432e701a1c146acab6a5b420b75dd35105e5d"
		"       22 5820"
		"          f0b7cb3ebf62594b9e8d9870b1a9154ab50cdd2c1e6e861490b82d92f09e1984"
		"   06 50"
		"      4d727d4dc01404d7e9590de7f04d89ca"
	>();
	CTAP_clientPIN cp;
	uint8_t status;
	status = test_ctap_parse_client_pin(request.data(), request.size(), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_clientPIN_pinUvAuthProtocol) |
		ctap_param_to_mask(CTAP_clientPIN_subCommand) |
		ctap_param_to_mask(CTAP_clientPIN_keyAgreement) |
		ctap_param_to_mask(CTAP_clientPIN_pinHashEnc);
	EXPECT_EQ(cp.present, expected_present);
	EXPECT_EQ(cp.pinUvAuthProtocol, 1);
	EXPECT_EQ(cp.subCommand, CTAP_clientPIN_subCmd_getPinToken);
	EXPECT_EQ(cp.keyAgreement.kty, 2);
	EXPECT_EQ(cp.keyAgreement.crv, 1);
	EXPECT_SAME_BYTES(cp.keyAgreement.pubkey.x, &request[17]);
	EXPECT_SAME_BYTES(cp.keyAgreement.pubkey.y, &request[52]);
	EXPECT_EQ(cp.pinHashEnc_size, 16);
	EXPECT_SAME_BYTES_S(16, cp.pinHashEnc, &request[86]);
}

} // namespace
