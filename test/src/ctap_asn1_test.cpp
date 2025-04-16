#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
#include <utils.h>
}
namespace {

class CtapAsn1Test : public testing::Test {
protected:
	uint8_t asn1_der_sig[72]{};
	size_t asn1_der_sig_size{};

	CtapAsn1Test() = default;

	void test(const std::array<uint8_t, 64> &signature) {
		ctap_convert_to_asn1_der_ecdsa_sig_value(
			signature.data(),
			asn1_der_sig,
			&asn1_der_sig_size
		);
	}

};

TEST_F(CtapAsn1Test, WebAuthnExample) {
	auto signature = hex::bytes<
		"3d46287b8c6e8c8c261c1b88f273b09a32a6cf2809fd6e30d5a79f2637008f54"
		"4e72236ea390a9a17bcf5f7a09d63ab2176c92bb8e36c04198a27b909b6e8f13"
	>();
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types
	auto expected_der = hex::bytes<
		"304402203d46287b8c6e8c8c261c1b88f273b09a32a6cf2809fd6e30d5a79f2637008f5402204e72236ea390a9a17bcf5f7a09d63ab2176c92bb8e36c04198a27b909b6e8f13"
	>();
	test(signature);
	EXPECT_EQ(asn1_der_sig_size, expected_der.size());
	EXPECT_SAME_BYTES_S(expected_der.size(), asn1_der_sig, expected_der.data());
}

TEST_F(CtapAsn1Test, Random1) {
	auto signature = hex::bytes<
		"1f52efe198918cbd6f25dbaff9a91b255aa86bc14b93e6e34e5a48fe6520eac9"
		"f5c7f38f8c75e7eff59578ee9efd5127e37057116f4d08e638e619a3688a6d2c"
	>();
	auto expected_der = hex::bytes<
		"304502201f52efe198918cbd6f25dbaff9a91b255aa86bc14b93e6e34e5a48fe6520eac9022100f5c7f38f8c75e7eff59578ee9efd5127e37057116f4d08e638e619a3688a6d2c"
	>();
	test(signature);
	EXPECT_EQ(asn1_der_sig_size, expected_der.size());
	EXPECT_SAME_BYTES_S(expected_der.size(), asn1_der_sig, expected_der.data());
}

TEST_F(CtapAsn1Test, AllZero) {
	auto signature = hex::bytes<
		"0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000"
	>();
	auto expected_der = hex::bytes<
		"3006020100020100"
	>();
	test(signature);
	EXPECT_EQ(asn1_der_sig_size, expected_der.size());
	EXPECT_SAME_BYTES_S(expected_der.size(), asn1_der_sig, expected_der.data());
}

TEST_F(CtapAsn1Test, MaximumSize) {
	auto signature = hex::bytes<
		"8000000000000000000000000000000000000000000000000000000000000000"
		"8000000000000000000000000000000000000000000000000000000000000000"
	>();
	auto expected_der = hex::bytes<
		"304602210080000000000000000000000000000000000000000000000000000000000000000221008000000000000000000000000000000000000000000000000000000000000000"
	>();
	test(signature);
	EXPECT_EQ(asn1_der_sig_size, expected_der.size());
	EXPECT_SAME_BYTES_S(expected_der.size(), asn1_der_sig, expected_der.data());
}

} // namespace
