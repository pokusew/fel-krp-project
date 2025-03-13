#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <cstring>
#include <utility>
#include <vector>
extern "C" {
#include <sha256.h>
}
namespace {

constexpr size_t SHA256_INTERNAL_BLOCK_SIZE = 64;
constexpr size_t SHA256_OUTPUT_SIZE = 32;

class InputHashPair {

public:
	const std::string name;
	const std::vector<uint8_t> input;
	const std::array<uint8_t, SHA256_OUTPUT_SIZE> expected_hash;

	template<size_t N>
	InputHashPair(
		std::string name,
		const std::array<uint8_t, N> &input,
		const std::array<uint8_t, SHA256_OUTPUT_SIZE> &expected_hash
	) :
		name(std::move(name)),
		input(input.data(), &input.data()[N]),
		expected_hash(expected_hash) {}

	template<size_t N>
	InputHashPair(
		std::string name,
		const char (&input)[N],
		const std::array<uint8_t, SHA256_OUTPUT_SIZE> &expected_hash
	) :
		name(std::move(name)),
		input(input, &input[N - 1]),
		expected_hash(expected_hash) {}
};

class Sha256Test : public testing::TestWithParam<InputHashPair> {

};

TEST_P(Sha256Test, ComputesHash) {

	const auto &expected_hash = GetParam().expected_hash;
	const auto &input = GetParam().input;

	std::array<uint8_t, SHA256_OUTPUT_SIZE> hash{};

	SHA256_CTX sha256_ctx; // NOLINT(*-pro-type-member-init)
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, input.data(), input.size());
	sha256_final(&sha256_ctx, hash.data());

	EXPECT_SAME_BYTES_S(SHA256_OUTPUT_SIZE, hash.data(), expected_hash.data());

}

INSTANTIATE_TEST_SUITE_P(
	TestVectors,
	Sha256Test,
	testing::Values(
		InputHashPair(
			"ZeroLengthInput",
			hex::bytes<"">(),
			hex::bytes<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">()
		),
		InputHashPair(
			"Random1",
			hex::bytes<
				"fa8148e2156c99abccbcd15dcaae2122e2afa542260c81716c55b834fcaa5391"
				"2bc69d116dd8e3da9b9e9c6a4ff065748dc15396400f5cc76324bbde8eacf449"
			>(),
			hex::bytes<"e85fede57c8186e9e9e4a156eeac3c4d1255b80ba0becb8c2f05bbd60e1493d6">()
		),
		// three test cases from https://github.com/B-Con/crypto-algorithms/blob/master/sha256_test.c
		InputHashPair(
			"GH1",
			"abc",
			hex::bytes<"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad">()
		),
		InputHashPair(
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
