#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctaphid.h>
#include <utils.h>
}
namespace {


class CtapCtaphidTest : public testing::Test {
protected:
	ctaphid_state_t ctaphid{};
	ctaphid_process_packet_result_t result{};
	uint8_t error_code{};

	CtapCtaphidTest() {
		ctaphid_init(&ctaphid);
	}

	void test_ctaphid_process_packet(const std::array<uint8_t, sizeof(ctaphid_packet_t)> &packet) {
		result = ctaphid_process_packet(
			&ctaphid,
			reinterpret_cast<const ctaphid_packet_t *>(packet.data()),
			&error_code
		);
	}

};

TEST_F(CtapCtaphidTest, InvalidChannel0) {
	auto packet = hex::bytes<
		"00000000" // channel id (32 bits)
		"86" // type (1 bit) + cmd (7 bits): initialization packet, CTAPHID_PING
		"0001" // payload length (big-endian): 1 byte
		// payload
		// data ( bytes)
		"ab"
		// zero bytes up to the fixed packet size (HID report size)
		"00000000000000"
		"00000000000000000000000000000000"
		"00000000000000000000000000000000"
		"0000000000000000000000000000000000"
	>();
	test_ctaphid_process_packet(packet);
	EXPECT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_CHANNEL);
}

TEST_F(CtapCtaphidTest, AlocateChannel) {
	auto packet = hex::bytes<
		"ffffffff" // channel id (32 bits)
		"86" // type (1 bit) + cmd (7 bits): initialization packet, CTAPHID_INIT
		"0008" // payload length (big-endian): 8 bytes
		// payload
		// nonce (8 bytes)
		"abcdef0102030405"
		// zero bytes up to the fixed packet size (HID report size)
		"00000000000000000000000000000000"
		"00000000000000000000000000000000"
		"0000000000000000000000000000000000"
	>();
	test_ctaphid_process_packet(packet);
	EXPECT_EQ(result, CTAPHID_RESULT_ALLOCATE_CHANNEL);
}

} // namespace
