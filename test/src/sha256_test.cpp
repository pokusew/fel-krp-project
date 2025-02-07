#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cstring>
extern "C" {
#include <sha256.h>
}
namespace {

constexpr size_t SHA256_INTERNAL_BLOCK_SIZE = 64;
constexpr size_t SHA256_OUTPUT_SIZE = 32;

struct input_hash_pair {
	const std::string name;
	const uint8_t *input_data;
	const size_t input_size;
	const std::array<uint8_t, SHA256_OUTPUT_SIZE> expected_hash;

	template<size_t N>
	static input_hash_pair create(
		const std::string &name,
		const std::array<uint8_t, N> &input,
		const std::array<uint8_t, SHA256_OUTPUT_SIZE> &expected_hash
	) {
		uint8_t *input_data = new uint8_t[N];
		// TODO: better solution
		std::memcpy(input_data, input.data(), N);
		return input_hash_pair{name, input_data, N, expected_hash};
	}

	template<size_t N>
	static input_hash_pair create(
		const std::string &name,
		const char (&input)[N],
		const std::array<uint8_t, SHA256_OUTPUT_SIZE> &expected_hash
	) {
		uint8_t *input_data = new uint8_t[N - 1];
		// TODO: better solution
		std::memcpy(input_data, input, N - 1);
		return input_hash_pair{name, input_data, N - 1, expected_hash};
	}
};

class Sha256Test : public testing::TestWithParam<input_hash_pair> {

};

TEST_P(Sha256Test, ComputesHash) {

	const auto expected_hash = GetParam().expected_hash;
	const auto input_data = GetParam().input_data;
	const auto input_size = GetParam().input_size;

	std::array<uint8_t, SHA256_OUTPUT_SIZE> hash{};

	SHA256_CTX sha256_ctx; // NOLINT(*-pro-type-member-init)
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, input_data, input_size);
	sha256_final(&sha256_ctx, hash.data());

	EXPECT_SAME_BYTES_S(SHA256_OUTPUT_SIZE, hash.data(), expected_hash.data());

}

INSTANTIATE_TEST_SUITE_P(
	TestVectors,
	Sha256Test,
	testing::Values(
		input_hash_pair::create(
			"ZeroLengthInput",
			hex::bytes<"">(),
			hex::bytes<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">()
		),
		input_hash_pair::create(
			"Random1",
			hex::bytes<
				"fa8148e2156c99abccbcd15dcaae2122e2afa542260c81716c55b834fcaa5391"
				"2bc69d116dd8e3da9b9e9c6a4ff065748dc15396400f5cc76324bbde8eacf449"
			>(),
			hex::bytes<"e85fede57c8186e9e9e4a156eeac3c4d1255b80ba0becb8c2f05bbd60e1493d6">()
		),
		// three test cases from https://github.com/B-Con/crypto-algorithms/blob/master/sha256_test.c
		input_hash_pair::create(
			"GH1",
			"abc",
			hex::bytes<"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad">()
		),
		input_hash_pair::create(
			"GH2",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			hex::bytes<"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1">()
		)
	),
	[](const testing::TestParamInfo<Sha256Test::ParamType> &info) {
		return info.param.name;
	}
);

}
