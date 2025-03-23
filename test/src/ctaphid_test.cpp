#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctaphid.h>
#include <utils.h>
}
namespace {

constexpr auto init_packet(
	uint32_t cid,
	ctaphid_command_t cmd,
	uint16_t total_payload_length
) {
	assert((cmd & 0x80) == 0x80);
	ctaphid_packet_t packet{};
	packet.cid = cid;
	packet.pkt.init.cmd = cmd;
	packet.pkt.init.bcnt = lion_htons(total_payload_length);
	return packet;
}

template<size_t N>
constexpr auto init_packet(
	uint32_t cid,
	ctaphid_command_t cmd,
	uint16_t total_payload_length,
	std::array<uint8_t, N> payload
) {
	auto packet = init_packet(cid, cmd, total_payload_length);
	std::copy_n(payload.begin(), min(sizeof(packet.pkt.init.payload), payload.size()), packet.pkt.init.payload);
	return packet;
}

constexpr auto cont_packet(
	uint32_t cid,
	uint8_t seq
) {
	assert((seq & 0x80) == 0x00);
	ctaphid_packet_t packet{};
	packet.cid = cid;
	packet.pkt.cont.seq = seq;
	return packet;
}

template<size_t N>
constexpr auto cont_packet(
	uint32_t cid,
	uint8_t seq,
	std::array<uint8_t, N> payload
) {
	auto packet = cont_packet(cid, seq);
	std::copy_n(payload.begin(), min(sizeof(packet.pkt.cont.payload), payload.size()), packet.pkt.cont.payload);
	return packet;
}

class CtapCtaphidTest : public testing::Test {
protected:
	ctaphid_state_t ctaphid{};
	ctaphid_process_packet_result_t result{};
	uint8_t error_code{};

	CtapCtaphidTest() {
		ctaphid_init(&ctaphid);
	}

	void test_ctaphid_process_packet(ctaphid_packet_t packet) {
		result = ctaphid_process_packet(
			&ctaphid,
			&packet,
			&error_code
		);
	}

};

TEST_F(CtapCtaphidTest, InvalidChannelZero) {
	test_ctaphid_process_packet(init_packet(
		0,
		CTAPHID_PING,
		2
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_CHANNEL);
}

TEST_F(CtapCtaphidTest, AlocateChannel) {

	EXPECT_EQ(ctaphid.highest_allocated_cid, 0);

	auto nonce = hex::bytes<"abcdef0102030405">();
	test_ctaphid_process_packet(init_packet(
		CTAPHID_BROADCAST_CID,
		CTAPHID_INIT,
		8,
		nonce
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ALLOCATE_CHANNEL);

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	EXPECT_EQ(ctaphid.highest_allocated_cid, 1);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		0
	));
	EXPECT_EQ(result, CTAPHID_RESULT_MESSAGE);

}

TEST_F(CtapCtaphidTest, PayloadLengthExceedsMaxLimit) {
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	EXPECT_EQ(ctaphid.highest_allocated_cid, 1);
	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_MAX_PAYLOAD_LENGTH + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_LENGTH);
}

TEST_F(CtapCtaphidTest, PingTwoPackets) {

	const uint32_t test_cid = 1;
	const ctaphid_command_t test_cmd = CTAPHID_PING;
	const uint16_t test_length = CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1;
	std::array<uint8_t, test_length> test_message{};
	test_message[0] = 0xab;
	test_message[test_length - 1] = 0xcd;

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		test_cmd,
		test_length,
		test_message
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	test_ctaphid_process_packet(cont_packet(
		test_cid,
		0,
		std::array<uint8_t, 1>{test_message[test_length - 1]}
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);

	EXPECT_EQ(ctaphid.buffer.cid, test_cid);
	EXPECT_EQ(ctaphid.buffer.cmd, test_cmd);
	EXPECT_EQ(ctaphid.buffer.payload_length, test_length);
	EXPECT_EQ(ctaphid.buffer.offset, test_length);
	EXPECT_SAME_BYTES_S(test_length, ctaphid.buffer.payload, test_message.data());

}

TEST_F(CtapCtaphidTest, PingTwoPacketsInvalidSeq) {

	const uint32_t test_cid = 1;
	const uint16_t test_length = CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1;
	std::array<uint8_t, test_length> test_message{};
	test_message[0] = 0xab;
	test_message[test_length - 1] = 0xcd;

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_PING,
		test_length,
		test_message
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	test_ctaphid_process_packet(cont_packet(
		test_cid,
		1,
		std::array<uint8_t, 1>{test_message[test_length - 1]}
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_SEQ);

}

TEST_F(CtapCtaphidTest, SpuriousContinuationPacket) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, test_cid);

	test_ctaphid_process_packet(cont_packet(test_cid, 0));
	ASSERT_EQ(result, CTAPHID_RESULT_IGNORED);

}

TEST_F(CtapCtaphidTest, CancelInvalidLength) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_CANCEL,
		5 // only 0 allowed
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_LENGTH);

}

TEST_F(CtapCtaphidTest, CancelIgnoredBecauseNoCborRequestInProgress) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_CANCEL,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_IGNORED);

}

TEST_F(CtapCtaphidTest, CancelIgnoredOnNonActiveChannel) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), true);
	ASSERT_EQ(ctaphid.highest_allocated_cid, 2);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_CANCEL,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_IGNORED);

}

} // namespace
