#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
#include "ctaphid.h"
extern "C" {
#include <ctap.h>
#include <utils.h>
}
namespace {

void print_ctap_string(const ctap_string_t &str) {
	printf(
		"ctap_string (%" PRIsz "): %.*s" nl,
		str.size, (int) str.size, str.data
	);
}

struct test_data {
	const char *name;
	const size_t max_size;
	const ctap_string_t input_str;
	const ctap_string_t expected_str;
};

class CtapStringRpIdTruncationTest : public testing::TestWithParam<test_data> {

};


TEST_P(CtapStringRpIdTruncationTest, CtapMaybeTruncateRpId) {

	const auto max_size = GetParam().max_size;
	const auto &input_str = GetParam().input_str;
	const auto &expected_str = GetParam().expected_str;

	printf("input ");
	print_ctap_string(input_str);
	printf("max_size = %" PRIsz nl, max_size);
	printf("expected ");
	print_ctap_string(expected_str);

	uint8_t storage_buffer[max_size];
	size_t stored_size;
	ctap_maybe_truncate_rp_id(
		&input_str,
		storage_buffer,
		sizeof(storage_buffer),
		&stored_size
	);
	EXPECT_TRUE(stored_size <= sizeof(storage_buffer));
	EXPECT_EQ(stored_size, expected_str.size);
	EXPECT_SAME_BYTES_S(stored_size, storage_buffer, expected_str.data);

}

class CtapStringTruncationTest : public testing::TestWithParam<test_data> {

};


TEST_P(CtapStringTruncationTest, CtapMaybeTruncateString) {

	const auto max_size = GetParam().max_size;
	const auto &input_str = GetParam().input_str;
	const auto &expected_str = GetParam().expected_str;

	printf("input ");
	print_ctap_string(input_str);
	printf("max_size = %" PRIsz nl, max_size);
	printf("expected ");
	print_ctap_string(expected_str);

	uint8_t storage_buffer[max_size];
	size_t stored_size;
	ctap_maybe_truncate_string(
		&input_str,
		storage_buffer,
		sizeof(storage_buffer),
		&stored_size
	);
	EXPECT_TRUE(stored_size <= sizeof(storage_buffer));
	EXPECT_EQ(stored_size, expected_str.size);
	EXPECT_SAME_BYTES_S(stored_size, storage_buffer, expected_str.data);

}

INSTANTIATE_TEST_SUITE_P(
	ExamplesFromCtapSpec,
	CtapStringRpIdTruncationTest,
	testing::Values(
		// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
		test_data{
			"NoTruncation", 32,
			ctap_str("example.com"),
			ctap_str("example.com")
		},
		test_data{
			"TruncationOnTheLeft", 32,
			ctap_str("myfidousingwebsite.hostingprovider.net"),
			ctap_str("\xe2\x80\xa6ngwebsite.hostingprovider.net")
		},
		test_data{
			"NoTruncationAppliedToStringsOfLength32", 32,
			ctap_str("mygreatsite.hostingprovider.info"),
			ctap_str("mygreatsite.hostingprovider.info")
		},
		test_data{
			"ProtocolStringsArePreservedIfPossible", 32,
			ctap_str("otherprotocol://myfidousingwebsite.hostingprovider.net"),
			ctap_str("otherprotocol:…ingprovider.net")
		},
		test_data{
			"ProtocolStringsMayConsumeTheEntireSpace", 32,
			ctap_str("veryexcessivelylargeprotocolname://example.com"),
			ctap_str("veryexcessivelylargeprotocolname")
		}
	),
	[](const testing::TestParamInfo<CtapStringRpIdTruncationTest::ParamType> &info) {
		return info.param.name;
	}
);

INSTANTIATE_TEST_SUITE_P(
	Basic,
	CtapStringTruncationTest,
	testing::Values(
		test_data{
			"NoTruncation", 5,
			ctap_str("alice"),
			ctap_str("alice")
		},
		test_data{
			"TruncationOnTheLeft", 3,
			ctap_str("alice"),
			ctap_str("ali")
		}
	),
	[](const testing::TestParamInfo<CtapStringRpIdTruncationTest::ParamType> &info) {
		return info.param.name;
	}
);

} // namespace
