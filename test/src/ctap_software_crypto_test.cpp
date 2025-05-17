#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cstring>
#include <utility>
#include <vector>
extern "C" {
#include <ctap_crypto_software.h>
}
namespace {

TEST(CtapSoftwareCryptoTest, RngSeed0Size0) {

	const uint32_t seed = 0;

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);

	uint8_t buffer[1]; // zero-length variable-length arrays not allowed

	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, 0), CTAP_CRYPTO_OK);

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size1) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e5">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size4) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size5) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870f1">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size6) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870f121">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size7) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870f121d3">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size8) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870f121d360">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

TEST(CtapSoftwareCryptoTest, RngSeed0Size9) {

	const uint32_t seed = 0;
	auto expected_random = hex::bytes<"e502f870f121d3605a">();

	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ASSERT_EQ(crypto.init(&crypto, seed), CTAP_CRYPTO_OK);
	uint8_t buffer[expected_random.size()];
	ASSERT_EQ(crypto.rng_generate_data(&crypto, buffer, expected_random.size()), CTAP_CRYPTO_OK);
	EXPECT_SAME_BYTES_S(expected_random.size(), buffer, expected_random.data());

}

}
