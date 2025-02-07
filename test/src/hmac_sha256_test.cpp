#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cstring>
extern "C" {
#include <hmac.h>
}
namespace {

constexpr size_t SHA256_INTERNAL_BLOCK_SIZE = 64;
constexpr size_t SHA256_OUTPUT_SIZE = 32;

struct input_hash_pair {
	const std::string name;
	const uint8_t *key_data;
	const size_t key_size;
	const uint8_t *input_data;
	const size_t input_size;
	const std::array<uint8_t, SHA256_OUTPUT_SIZE> expected_hmac;

	template<size_t N>
	static uint8_t *copy_input(const std::array<uint8_t, N> &input, size_t &num_bytes) {
		num_bytes = input.size();
		auto *raw = new uint8_t[input.size()];
		std::memcpy(raw, input.data(), input.size());
		return raw;
	}

	template<size_t N>
	static uint8_t *copy_input(const char (&input)[N], size_t &num_bytes) {
		num_bytes = N - 1;
		auto *raw = new uint8_t[N - 1];
		std::memcpy(raw, input, N - 1);
		return raw;
	}

	template<typename KeyType, typename InputType>
	static input_hash_pair create(
		const std::string &name,
		const KeyType &key,
		const InputType &input,
		const std::array<uint8_t, SHA256_OUTPUT_SIZE> &expected_hmac
	) {
		size_t key_size;
		uint8_t *key_data = copy_input(key, key_size);
		size_t input_size;
		uint8_t *input_data = copy_input(input, input_size);
		return input_hash_pair{name, key_data, key_size, input_data, input_size, expected_hmac};
	}
};

class HmacSha256Test : public testing::TestWithParam<input_hash_pair> {

};

TEST_P(HmacSha256Test, ComputesHmac) {

	const auto expected_hmac = GetParam().expected_hmac;
	const auto key_data = GetParam().key_data;
	const auto key_size = GetParam().key_size;
	const auto input_data = GetParam().input_data;
	const auto input_size = GetParam().input_size;

	std::array<uint8_t, SHA256_OUTPUT_SIZE> hmac{};

	hmac_sha256_ctx_t ctx; // NOLINT(*-pro-type-member-init)
	hmac_sha256_init(&ctx, key_data, key_size);
	hmac_sha256_update(&ctx, input_data, input_size);
	hmac_sha256_final(&ctx, hmac.data());

	EXPECT_SAME_BYTES_S(SHA256_OUTPUT_SIZE, hmac.data(), expected_hmac.data());

}

INSTANTIATE_TEST_SUITE_P(
	TestVectors,
	HmacSha256Test,
	testing::Values(
		// https://en.wikipedia.org/wiki/HMAC#Examples
		input_hash_pair::create(
			"Wiki1",
			"key",
			"The quick brown fox jumps over the lazy dog",
			hex::bytes<"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8">()
		),
		input_hash_pair::create(
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
