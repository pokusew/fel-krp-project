#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap_parse.h>
}
namespace {

uint8_t test_ctap_parse_make_credential(const uint8_t *data, size_t data_size, CTAP_makeCredential *mc) {
	CborParser parser;
	CborValue it;
	uint8_t ret;
	ctap_parse_check(ctap_init_cbor_parser(data, data_size, &parser, &it));
	return ctap_parse_make_credential(&it, mc);
}

TEST(CtapParseMakeCredentialTest, InvalidCbor) {
	auto params = hex::bytes<"ff">();
	CTAP_makeCredential mc;
	uint8_t status;
	status = test_ctap_parse_make_credential(params.data(), params.size(), &mc);
	ASSERT_EQ(status, CTAP2_ERR_INVALID_CBOR);
}

TEST(CtapParseMakeCredentialTest, Dummy) {
	auto params = hex::bytes<
		// {
		//     1: h'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		//     2: {"id": ".dummy"},
		//     3: {"id": h'01', "name": "dummy"},
		//     4: [{"alg": -7, "type": "public-key"}],
		//     8: h'',
		//     9: 1,
		// }
		"a6                                     " // map(6)
		"   01                                  " //   unsigned(1)
		"   58 20                               " //   bytes(32)
		"      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		"   02                                  " //   unsigned(2)
		"   a1                                  " //   map(1)
		"      62                               " //     text(2)
		"         6964                          " //       "id"
		"      66                               " //     text(6)
		"         2e64756d6d79                  " //       ".dummy"
		"   03                                  " //   unsigned(3)
		"   a2                                  " //   map(2)
		"      62                               " //     text(2)
		"         6964                          " //       "id"
		"      41                               " //     bytes(1)
		"         01                            " //       "\x01"
		"      64                               " //     text(4)
		"         6e616d65                      " //       "name"
		"      65                               " //     text(5)
		"         64756d6d79                    " //       "dummy"
		"   04                                  " //   unsigned(4)
		"   81                                  " //   array(1)
		"      a2                               " //     map(2)
		"         63                            " //       text(3)
		"            616c67                     " //         "alg"
		"         26                            " //       negative(-7)
		"         64                            " //       text(4)
		"            74797065                   " //         "type"
		"         6a                            " //       text(10)
		"            7075626c69632d6b6579       " //         "public-key"
		"   08                                  " //   unsigned(8)
		"   40                                  " //   bytes(0)
		"                                       " //     ""
		"   09                                  " //   unsigned(9)
		"   01                                  " //   unsigned(1)
	>();
	CTAP_makeCredential mc;
	uint8_t status;
	status = test_ctap_parse_make_credential(params.data(), params.size(), &mc);
	ASSERT_EQ(status, CTAP2_OK);

	constexpr uint32_t expected_present =
		ctap_param_to_mask(CTAP_makeCredential_clientDataHash) |
		ctap_param_to_mask(CTAP_makeCredential_rp) |
		ctap_param_to_mask(CTAP_makeCredential_user) |
		ctap_param_to_mask(CTAP_makeCredential_pubKeyCredParams) |
		ctap_param_to_mask(CTAP_makeCredential_pinUvAuthParam) |
		ctap_param_to_mask(CTAP_makeCredential_pinUvAuthProtocol);
	EXPECT_EQ(mc.present, expected_present);

	auto expected_clientDataHash = hex::bytes<
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	>();
	EXPECT_SAME_BYTES(mc.clientDataHash, expected_clientDataHash.data());

	auto expected_rpId = hex::bytes<"2e64756d6d79">();
	EXPECT_EQ(mc.rpId.id_size, expected_rpId.size());
	EXPECT_SAME_BYTES_S(expected_rpId.size(), mc.rpId.id, expected_rpId.data());

	auto expected_userId = hex::bytes<"01">();
	EXPECT_EQ(mc.user.id_size, expected_userId.size());
	EXPECT_SAME_BYTES_S(expected_userId.size(), mc.user.id, expected_userId.data());

	EXPECT_EQ(mc.user.displayName_present, false);

	EXPECT_EQ(mc.pinUvAuthParam_size, 0);
	EXPECT_EQ(mc.pinUvAuthProtocol, 1);
}

} // namespace
