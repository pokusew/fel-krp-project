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
	uint32_t current_time = 0;

	CtapCtaphidTest() {
		ctaphid_init(&ctaphid);
	}

	void increase_time(uint32_t increase) {
		current_time += increase;
	}

	void test_ctaphid_process_packet(ctaphid_packet_t packet) {
		result = ctaphid_process_packet(
			&ctaphid,
			&packet,
			current_time,
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

TEST_F(CtapCtaphidTest, InvalidChannelNonZeroHigherThanAllocated) {
	EXPECT_EQ(ctaphid.highest_allocated_cid, 0);
	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		2
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_CHANNEL);
}

TEST_F(CtapCtaphidTest, PayloadLengthExceedsMaxLimit) {
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid.highest_allocated_cid, 1);
	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_MAX_PAYLOAD_LENGTH + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_LENGTH);
}

TEST_F(CtapCtaphidTest, AlocateChannelNumberWhenNumbersDepleted) {
	const uint32_t max_channel_number = CTAPHID_BROADCAST_CID - 1;
	ctaphid.highest_allocated_cid = CTAPHID_BROADCAST_CID - 2;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), max_channel_number);
	EXPECT_EQ(ctaphid.highest_allocated_cid, max_channel_number);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 0);
	EXPECT_EQ(ctaphid.highest_allocated_cid, max_channel_number);
}

TEST_F(CtapCtaphidTest, InitInvalidLength) {
	test_ctaphid_process_packet(init_packet(
		CTAPHID_BROADCAST_CID,
		CTAPHID_INIT,
		4 // only 8 allowed
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_INVALID_LENGTH);
}

TEST_F(CtapCtaphidTest, InitAlocateChannel) {

	EXPECT_EQ(ctaphid.highest_allocated_cid, 0);

	auto nonce = hex::bytes<"abcdef0102030405">();
	test_ctaphid_process_packet(init_packet(
		CTAPHID_BROADCAST_CID,
		CTAPHID_INIT,
		8,
		nonce
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ALLOCATE_CHANNEL);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		0
	));
	EXPECT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);

}

TEST_F(CtapCtaphidTest, InitAbortAndResychronizeNoActualReset) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	auto nonce = hex::bytes<"abcdef0102030405">();
	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_INIT,
		8,
		nonce
	));
	ASSERT_EQ(result, CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE);

}

TEST_F(CtapCtaphidTest, InitAbortAndResychronizeWithActualReset) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	auto nonce = hex::bytes<"abcdef0102030405">();
	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_INIT,
		8,
		nonce
	));
	ASSERT_EQ(result, CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);

}

TEST_F(CtapCtaphidTest, PingTwoPackets) {

	const uint32_t test_cid = 1;
	const ctaphid_command_t test_cmd = CTAPHID_PING;
	const uint16_t test_length = CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1;
	std::array<uint8_t, test_length> test_message{};
	test_message[0] = 0xab;
	test_message[test_length - 1] = 0xcd;

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		test_cmd,
		test_length,
		test_message
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);

	test_ctaphid_process_packet(cont_packet(
		test_cid,
		0,
		std::array<uint8_t, 1>{test_message[test_length - 1]}
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);
	EXPECT_EQ(ctaphid.buffer.cancel, false);

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

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

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
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	test_ctaphid_process_packet(cont_packet(test_cid, 0));
	ASSERT_EQ(result, CTAPHID_RESULT_IGNORED);

}

TEST_F(CtapCtaphidTest, CancelInvalidLength) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

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
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_CANCEL,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_IGNORED);

}

TEST_F(CtapCtaphidTest, CancelIgnoredOnNonActiveChannel) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);

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
	EXPECT_EQ(ctaphid.buffer.cancel, false);

}

TEST_F(CtapCtaphidTest, CancelOngoingCborRequest) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);

	auto payload = hex::bytes<"0b">(); // authenticatorSelection (0x0B)
	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_CBOR,
		1,
		payload
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);
	EXPECT_SAME_BYTES_S(payload.size(), ctaphid.buffer.payload, payload.data());

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_CANCEL,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_CANCEL);
	EXPECT_EQ(ctaphid.buffer.cancel, true);

}

TEST_F(CtapCtaphidTest, InitPacketWhileSameChannelBusyWithBuffering) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_PING,
		CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

}

TEST_F(CtapCtaphidTest, InitPacketWhileSameChannelBusyWithMessage) {

	const uint32_t test_cid = 1;
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), test_cid);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_PING,
		1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);

	test_ctaphid_process_packet(init_packet(
		test_cid,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

}

TEST_F(CtapCtaphidTest, InitPacketWhileOtherChannelBusyWithBuffering) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

}

TEST_F(CtapCtaphidTest, InitPacketWhileOtherChannelBusyWithMessage) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

}

TEST_F(CtapCtaphidTest, TransactionTimeout) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_BUFFERING);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_incomplete_message_timeout(&ctaphid, current_time), false);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), false);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

	increase_time(CTAPHID_TRANSACTION_TIMEOUT + 1);
	EXPECT_EQ(ctaphid_has_incomplete_message_timeout(&ctaphid, current_time), true);

	ctaphid_reset_to_idle(&ctaphid);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_incomplete_message_timeout(&ctaphid, current_time), false);

}

TEST_F(CtapCtaphidTest, ExplicitResetToIdle) {

	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 1);
	EXPECT_EQ(ctaphid_allocate_channel(&ctaphid), 2);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);

	test_ctaphid_process_packet(init_packet(
		1,
		CTAPHID_PING,
		1
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_ERROR);
	EXPECT_EQ(error_code, CTAP1_ERR_CHANNEL_BUSY);

	ctaphid_reset_to_idle(&ctaphid);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), true);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), false);

	test_ctaphid_process_packet(init_packet(
		2,
		CTAPHID_PING,
		0
	));
	ASSERT_EQ(result, CTAPHID_RESULT_MESSAGE);
	EXPECT_EQ(ctaphid_is_idle(&ctaphid), false);
	EXPECT_EQ(ctaphid_has_complete_message_ready(&ctaphid), true);

}

class CtaphidMessageToPacketsTest : public testing::Test {
protected:
	ctaphid_packet_t packets[CTAPHID_MESSAGE_MAX_NUM_PACKETS]{};
	size_t num_packets{};
	constexpr static ctaphid_packet_t zero_packet{};

	CtaphidMessageToPacketsTest() = default;

	void packet_handler(const ctaphid_packet_t *packet) {
		// memcpy(packets[num_packets], packet, sizeof(ctaphid_packet_t));
		constexpr size_t max_num_packets = sizeof(packets) / sizeof(ctaphid_packet_t);
		// ignore any packets that do not fit into the buffer
		if (num_packets < max_num_packets) {
			packets[num_packets] = *packet;
		}
		// but still count the total number of packets
		num_packets++;
		// the first time the limit is reached, fail this test case
		if (num_packets == max_num_packets) {
			GTEST_FATAL_FAILURE_("max_num_packets reached");
		}
	}

	template<size_t N>
	void test_ctaphid_message_to_packets(uint32_t cid, uint8_t cmd, const std::array<uint8_t, N> &payload) {
		num_packets = 0;
		auto handler = [this](const ctaphid_packet_t *packet) {
			packet_handler(packet);
		};
		ctaphid_message_to_packets(
			cid,
			cmd,
			payload.size(),
			payload.data(),
			[](const ctaphid_packet_t *packet, void *ctx) {
				(*reinterpret_cast<decltype(&handler)>(ctx))(packet);
			},
			&handler
		);
		// alternatively we could use this directly instead of the helper handler lambda
		// ctaphid_message_to_packets(
		// 	cid,
		// 	cmd,
		// 	payload.size(),
		// 	payload.data(),
		// 	[](const ctaphid_packet_t *packet, void *ctx) {
		// 		auto _this = reinterpret_cast<decltype(this)>(ctx);
		// 		_this->packet_handler(packet);
		// 	},
		// 	this
		// );
	}

};

// bcnt field is not aligned, AddressSanitizer throws warnings when pkt.init.bcnt is used
// directly in EXPECT_EQ
//   Reference binding to misaligned address ... for type 'const unsigned short',
//   which requires 2 byte alignment
// To avoid those, we use the following solution:
#define EXPECT_BCNT_EQ(unaligned_bcnt_field, expected_value) \
    {                                                        \
        uint16_t bcnt = (unaligned_bcnt_field);              \
        EXPECT_EQ(bcnt, expected_value);                     \
    }                                                        \
    ((void) 0)

TEST_F(CtaphidMessageToPacketsTest, ZeroLengthPayload) {
	const uint32_t test_cid = 11259375;
	const uint8_t test_cmd = CTAPHID_PING;
	auto payload = hex::bytes<"">();
	test_ctaphid_message_to_packets(test_cid, test_cmd, payload);
	ASSERT_EQ(num_packets, 1);
	const auto &init_p = packets[0];
	EXPECT_EQ(init_p.cid, test_cid);
	EXPECT_EQ(init_p.pkt.init.cmd, test_cmd);
	EXPECT_BCNT_EQ(init_p.pkt.init.bcnt, lion_ntohs(payload.size()));
	EXPECT_SAME_BYTES(init_p.pkt.init.payload, zero_packet.pkt.init.payload);
}

TEST_F(CtaphidMessageToPacketsTest, PayloadFitsExactlyIntoInit) {
	const uint32_t test_cid = 11259375;
	const uint8_t test_cmd = CTAPHID_PING;
	auto payload = std::array<uint8_t, CTAPHID_PACKET_INIT_PAYLOAD_SIZE>{0xab};
	test_ctaphid_message_to_packets(test_cid, test_cmd, payload);
	ASSERT_EQ(num_packets, 1);
	const auto &init = packets[0];
	EXPECT_EQ(init.cid, test_cid);
	EXPECT_EQ(init.pkt.init.cmd, test_cmd);
	EXPECT_BCNT_EQ(init.pkt.init.bcnt, lion_ntohs(payload.size()));
	EXPECT_SAME_BYTES(init.pkt.init.payload, payload.data());
}

TEST_F(CtaphidMessageToPacketsTest, InitAndSingleCont) {
	const uint32_t test_cid = 11259375;
	const uint8_t test_cmd = CTAPHID_PING;
	auto payload = std::array<uint8_t, CTAPHID_PACKET_INIT_PAYLOAD_SIZE + 1>{0xab};
	payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE] = 0xcd;
	test_ctaphid_message_to_packets(test_cid, test_cmd, payload);
	ASSERT_EQ(num_packets, 2);
	const auto &init = packets[0];
	EXPECT_EQ(init.cid, test_cid);
	EXPECT_EQ(init.pkt.init.cmd, test_cmd);
	EXPECT_BCNT_EQ(init.pkt.init.bcnt, lion_ntohs(payload.size()));
	EXPECT_SAME_BYTES(init.pkt.init.payload, &payload[0]);
	const auto &cont = packets[1];
	EXPECT_EQ(cont.cid, test_cid);
	EXPECT_EQ(cont.pkt.cont.seq, 0);
	EXPECT_SAME_BYTES_S(1, cont.pkt.cont.payload, &payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE]);
	// check that the rest of the continuation packet is correctly zeroed
	EXPECT_SAME_BYTES_S(
		CTAPHID_PACKET_CONT_PAYLOAD_SIZE - 1,
		&cont.pkt.cont.payload[1],
		zero_packet.pkt.cont.payload
	);
}

TEST_F(CtaphidMessageToPacketsTest, InitAndTwoConts) {
	const uint32_t test_cid = 11259375;
	const uint8_t test_cmd = CTAPHID_PING;
	constexpr size_t test_payload_length = CTAPHID_PACKET_INIT_PAYLOAD_SIZE + CTAPHID_PACKET_CONT_PAYLOAD_SIZE + 1;
	auto payload = std::array<uint8_t, test_payload_length>{0xab};
	payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE] = 0xcd;
	payload[CTAPHID_PACKET_CONT_PAYLOAD_SIZE] = 0xef;
	test_ctaphid_message_to_packets(test_cid, test_cmd, payload);
	ASSERT_EQ(num_packets, 3);
	const auto &init = packets[0];
	EXPECT_EQ(init.cid, test_cid);
	EXPECT_EQ(init.pkt.init.cmd, test_cmd);
	EXPECT_BCNT_EQ(init.pkt.init.bcnt, lion_ntohs(payload.size()));
	EXPECT_SAME_BYTES(init.pkt.init.payload, &payload[0]);
	const auto &cont0 = packets[1];
	EXPECT_EQ(cont0.cid, test_cid);
	EXPECT_EQ(cont0.pkt.cont.seq, 0);
	EXPECT_SAME_BYTES(cont0.pkt.cont.payload, &payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE]);
	const auto &cont1 = packets[2];
	EXPECT_EQ(cont1.cid, test_cid);
	EXPECT_EQ(cont1.pkt.cont.seq, 1);
	EXPECT_SAME_BYTES_S(
		1,
		cont1.pkt.cont.payload,
		&payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE + CTAPHID_PACKET_CONT_PAYLOAD_SIZE]
	);
	// check that the rest of the continuation packet is correctly zeroed
	EXPECT_SAME_BYTES_S(
		CTAPHID_PACKET_CONT_PAYLOAD_SIZE - 1,
		&cont1.pkt.cont.payload[1],
		zero_packet.pkt.cont.payload
	);
}

TEST(CtaphidCreateErrorPacketTest, SampleErrorCodes) {
	constexpr ctaphid_packet_t zero_packet{};
	ctaphid_packet_t packet;
	const uint32_t test_cid = 11259375;
	// value-parameterized test would be an overkill here
	const std::array<uint8_t, 2> error_codes = {CTAP2_OK, CTAP1_ERR_OTHER};
	for (const uint8_t &error_code : error_codes) {
		ctaphid_create_error_packet(&packet, test_cid, error_code);
		EXPECT_EQ(packet.pkt.init.cmd, CTAPHID_ERROR);
		EXPECT_BCNT_EQ(packet.pkt.init.bcnt, lion_htons(1));
		EXPECT_EQ(packet.pkt.init.payload[0], error_code);
		EXPECT_SAME_BYTES_S(
			sizeof(packet.pkt.init.payload) - 1,
			&packet.pkt.init.payload[1],
			&zero_packet.pkt.init.payload[1]
		);
	}
}

TEST(CtaphidCreateCtaphidInitResponsePacket, BasicChecks) {
	constexpr ctaphid_packet_t zero_packet{};
	ctaphid_packet_t packet;
	const uint32_t test_transport_cid = CTAPHID_BROADCAST_CID;
	const uint32_t test_response_cid = 11259375;
	constexpr auto test_nonce = hex::bytes<"a1b2c3d4e5f6a7b8">();
	const uint8_t capabilities = CTAPHID_CAPABILITY_WINK | CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_NMSG;
	ctaphid_create_ctaphid_init_response_packet(
		&packet,
		test_nonce.data(),
		test_transport_cid,
		test_response_cid,
		1,
		2,
		3,
		capabilities
	);
	static_assert(sizeof(packet.pkt.init.payload) >= sizeof(ctaphid_init_response_payload_t));
	EXPECT_EQ(packet.pkt.init.cmd, CTAPHID_INIT);
	EXPECT_BCNT_EQ(packet.pkt.init.bcnt, lion_htons(sizeof(ctaphid_init_response_payload_t)));
	auto payload = reinterpret_cast<ctaphid_init_response_payload_t *const>(&packet.pkt.init.payload);
	EXPECT_SAME_BYTES_S(test_nonce.size(), payload->nonce, test_nonce.data());
	EXPECT_EQ(payload->protocol_version, CTAPHID_PROTOCOL_VERSION);
	EXPECT_EQ(payload->version_major, 1);
	EXPECT_EQ(payload->version_minor, 2);
	EXPECT_EQ(payload->version_build, 3);
	EXPECT_EQ(payload->capabilities, capabilities);
	EXPECT_SAME_BYTES_S(
		sizeof(packet.pkt.init.payload) - sizeof(ctaphid_init_response_payload_t),
		&packet.pkt.init.payload[sizeof(ctaphid_init_response_payload_t)],
		&zero_packet.pkt.init.payload[sizeof(ctaphid_init_response_payload_t)]
	);
}

} // namespace
