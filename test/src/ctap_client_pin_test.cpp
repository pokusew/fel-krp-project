#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap.h>
}
namespace {

class CtapClientPinTest : public testing::Test {
protected:
	ctap_state_t ctap{};
	uint8_t response_status_code{};
	uint16_t response_data_length{};
	uint8_t *response_data{};
	uint8_t status{};

	CtapClientPinTest() {
		ctap_init(&ctap);
	}

	template<size_t N>
	void test_ctap_request(const std::array<uint8_t, N> &request) {
		status = ctap_request(
			&ctap,
			N, request.data(),
			&response_status_code, &response_data_length, &response_data
		);
	}

};

TEST_F(CtapClientPinTest, InvalidSubcommand) {
	auto request = hex::bytes<
		"06" // CTAP_CMD_CLIENT_PIN
		// {1: 1, 2: 9}
		"a2" // map(2)
		"01" //   unsigned(1)
		"01" //   unsigned(1)
		"02" //   unsigned(2)
		"09" //   unsigned(9)
	>();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_ERR_INVALID_SUBCOMMAND);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
}

TEST_F(CtapClientPinTest, GetPinRetries) {
	// 0x06 {1: 1, 2: 1}
	auto request = hex::bytes<"06 a2 01 01 02 01">();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<"a2 03 08 04 f4">();
	ASSERT_EQ(response_data_length, expected_response.size());
	EXPECT_SAME_BYTES_S(response_data_length, response_data, expected_response.data());
}

} // namespace
