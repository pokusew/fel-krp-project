#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
extern "C" {
#include <ctap.h>
}

namespace {

class CtapClientPinTest : public testing::Test {
protected:
	ctap_state_t ctap{};

	CtapClientPinTest() {
		ctap_init(&ctap);
	}

};

TEST_F(CtapClientPinTest, InvalidSubcommand) {
	// 0x06 {1: 1, 2: 9}
	const uint8_t request[] = "\x06\xa2\x01\x01\x02\x09";

	uint8_t response_status_code;
	uint16_t response_data_length;
	uint8_t *response_data;
	uint8_t status;

	status = ctap_request(
		&ctap,
		sizeof(request) - 1, request,
		&response_status_code, &response_data_length, &response_data
	);

	EXPECT_EQ(status, CTAP2_ERR_INVALID_SUBCOMMAND);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
}

TEST_F(CtapClientPinTest, GetPinRetries) {
	// 0x06 {1: 1, 2: 1}
	const uint8_t request[] = "\x06\xa2\x01\x01\x02\x01";

	uint8_t response_status_code;
	uint16_t response_data_length;
	uint8_t *response_data;
	uint8_t status;

	status = ctap_request(
		&ctap,
		sizeof(request) - 1, request,
		&response_status_code, &response_data_length, &response_data
	);

	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	// {3: 8, 4: false}
	const uint8_t expected_response[] = "\xa2\x03\x08\x04\xF4";
	ASSERT_EQ(response_data_length, sizeof(expected_response) - 1);
	EXPECT_SAME_BYTES_S(response_data_length, response_data, expected_response);
}

} // namespace
