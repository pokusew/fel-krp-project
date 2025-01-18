#include <gtest/gtest.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
extern "C" {
#include "ctap_parse.h"
}

namespace {

testing::AssertionResult SameBytes(
	const char *size_expr,
	const char *actual_expr,
	const char *expected_expr,
	size_t size,
	const uint8_t *actual,
	const uint8_t *expected
) {
	for (int i = 0; i < size; ++i) {
		if (actual[i] != expected[i]) {
			size_t field_width = std::max(strlen(actual_expr), strlen(expected_expr));
			return testing::AssertionFailure()
				<< fmt::format(
					"bytes differ when comparing {0} bytes ({1}):"
					"\n  {3:>{2}}: {4:02X}"
					"\n  {5:>{2}}: {6:02X}"
					"\n  {8:>{9}}  ^^ first diff at index = {7}",
					size, size_expr, field_width,
					actual_expr, fmt::join(actual, actual + size, " "),
					expected_expr, fmt::join(expected, expected + size, " "),
					i, "", field_width + (i * 3)
				);
		}
	}
	return testing::AssertionSuccess();
}

#define EXPECT_SAME_BYTES(actual, expected) EXPECT_PRED_FORMAT3(SameBytes, sizeof((actual)), (actual), (expected))

TEST(CtapParseClientPin, InvalidCbor) {
	const uint8_t request[] = {0xFF};
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request, sizeof(request), &cp);
	ASSERT_EQ(status, CTAP2_ERR_INVALID_CBOR);
}

// TODO: Consider not allowing CBOR messages that are NOT in the CTAP2 canonical CBOR encoding form.
// See 8. Message Encoding (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding)
TEST(CtapParseClientPin, RequestCborNotCanonical) {
	const uint8_t request[] = {0xA2, 0x02, 0x02, 0x01, 0x01};
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request, sizeof(request), &cp);
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
	const uint8_t request[] = {0xA2, 0x01, 0x01, 0x02, 0x02};
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request, sizeof(request), &cp);
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
	const uint8_t request[] = "\xa4\x01\x01\x02\x05\x03\xa5\x01\x02\x03\x38\x18\x20\x01\x21\x58" \
		"\x20\x39\x09\xe3\x89\xb5\x45\x66\x2b\xfb\xee\x67\x90\x5d\xd4\x32" \
		"\xe7\x01\xa1\xc1\x46\xac\xab\x6a\x5b\x42\x0b\x75\xdd\x35\x10\x5e" \
		"\x5d\x22\x58\x20\xf0\xb7\xcb\x3e\xbf\x62\x59\x4b\x9e\x8d\x98\x70" \
		"\xb1\xa9\x15\x4a\xb5\x0c\xdd\x2c\x1e\x6e\x86\x14\x90\xb8\x2d\x92" \
		"\xf0\x9e\x19\x84\x06\x50\x4d\x72\x7d\x4d\xc0\x14\x04\xd7\xe9\x59" \
		"\x0d\xe7\xf0\x4d\x89\xca";
	CTAP_clientPIN cp;
	uint8_t status;
	status = ctap_parse_client_pin(request, sizeof(request), &cp);
	ASSERT_EQ(status, CTAP2_OK);
	EXPECT_EQ(cp.pinUvAuthProtocol, 1);
	EXPECT_EQ(cp.subCommand, CTAP_clientPIN_subCmd_getPinToken);
	EXPECT_EQ(cp.keyAgreementPresent, true);
	EXPECT_EQ(cp.keyAgreement.kty, 2);
	EXPECT_EQ(cp.keyAgreement.crv, 1);
	const uint8_t expected_x[] = "\x39\x09\xe3\x89\xb5\x45\x66\x2b\xfb\xee\x67\x90\x5d\xd4\x32\xe7\x01\xa1\xc1\x46\xac\xab\x6a\x5b\x42\x0b\x75\xdd\x35\x10\x5e\x5d";
	const uint8_t expected_y[] = "\xf0\xb7\xcb\x3f\xbf\x62\x59\x4b\x9e\x8d\x98\x70\xb1\xa9\x15\x4a\xb5\x0c\xdd\x2c\x1e\x6e\x86\x14\x90\xb8\x2d\x92\xf0\x9e\x19\x84";
	EXPECT_SAME_BYTES(
		cp.keyAgreement.pubkey.x,
		expected_x
	);
	EXPECT_SAME_BYTES(
		cp.keyAgreement.pubkey.y,
		expected_y
	);
	EXPECT_EQ(cp.pinUvAuthParamPresent, false);
	EXPECT_EQ(cp.newPinEncSize, 0);
	EXPECT_EQ(cp.pinHashEncPresent, true);
	EXPECT_EQ(cp.permissionsPresent, false);
	EXPECT_EQ(cp.rpIdPresent, false);
}

} // namespace
