#include <gtest/gtest.h>
extern "C" {
#include "ctap_parse.h"
}

namespace {

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

} // namespace
