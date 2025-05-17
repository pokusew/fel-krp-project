#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cstring>
#include <utility>
#include <vector>
extern "C" {
#include <hmac.h>
#include <sha256.h>
}
namespace {

class InputHashPair {
public:
	const std::string name;
	const std::vector<uint8_t> key;
	const std::vector<uint8_t> input;
	const std::array<uint8_t, LIONKEY_SHA256_OUTPUT_SIZE> expected_hmac;

	template<size_t N>
	static std::vector<uint8_t> to_vector(const std::array<uint8_t, N> &input) {
		std::vector<uint8_t> vector(input.data(), &input.data()[N]);
		return vector;
	}

	template<size_t N>
	static std::vector<uint8_t> to_vector(const char (&input)[N]) {
		std::vector<uint8_t> vector(input, &input[N - 1]);
		return vector;
	}

	template<typename KeyType, typename InputType>
	InputHashPair(
		std::string name,
		const KeyType &key,
		const InputType &input,
		const std::array<uint8_t, LIONKEY_SHA256_OUTPUT_SIZE> &expected_hmac
	) :
		name(std::move(name)),
		key(to_vector(key)),
		input(to_vector(input)), expected_hmac(expected_hmac) {}

};

class HmacSha256Test : public testing::TestWithParam<InputHashPair> {

};

TEST_P(HmacSha256Test, ComputesHmac) {

	const auto &expected_hmac = GetParam().expected_hmac;
	const auto &key = GetParam().key;
	const auto &input = GetParam().input;

	std::array<uint8_t, LIONKEY_SHA256_OUTPUT_SIZE> hmac{};

	const hash_alg_t *const sha256 = &hash_alg_sha256;
	ASSERT_GT(sha256->ctx_size, 0);

	uint8_t sha256_ctx[sha256->ctx_size];

	const size_t hmac_sha256_ctx_size = hmac_get_context_size(sha256);

	ASSERT_EQ(hmac_sha256_ctx_size, sizeof(hash_alg_t *) + sizeof(void *) + sha256->block_size);

	uint8_t hmac_sha256_ctx[hmac_sha256_ctx_size];
	hmac_init(hmac_sha256_ctx, sha256, sha256_ctx, key.data(), key.size());
	hmac_update(hmac_sha256_ctx, input.data(), input.size());
	hmac_final(hmac_sha256_ctx, hmac.data());

	EXPECT_SAME_BYTES_S(LIONKEY_SHA256_OUTPUT_SIZE, hmac.data(), expected_hmac.data());

}

INSTANTIATE_TEST_SUITE_P(
	TestVectors,
	HmacSha256Test,
	testing::Values(
		// https://en.wikipedia.org/wiki/HMAC#Examples
		InputHashPair(
			"Wiki1",
			"key",
			"The quick brown fox jumps over the lazy dog",
			hex::bytes<"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8">()
		),
		InputHashPair(
			"LongKey1",
			hex::bytes<"da6f806764befd332f5571ad55d3d9957be01ae036fc8161d8a66e87642db49eccb41b2cc473190be39e3178ba901ff5c608228f46ade6ffd654d19302527a7e45798db3e6e23c27ce5661ee657607cf8c17df">(),
			"The quick brown fox jumps over the lazy dog",
			hex::bytes<"de5af7abdaaeb1e902e06e6b5d10a425e2ffb00bb969012db6ab17a8eb799fb1">()
		)
	),
	[](const testing::TestParamInfo<HmacSha256Test::ParamType> &info) {
		return info.param.name;
	}
);

}
