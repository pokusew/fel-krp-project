#include "ctaphid.h"
#include "utils.h"
#include <string.h>
#include <stdbool.h>

bool ctaphid_allocate_channel(ctaphid_state_t *state) {
	if (state->highest_allocated_cid + 1 == CTAPHID_BROADCAST_CID) {
		return false;
	}
	state->highest_allocated_cid++;
	return true;
}

static void reset_buffer(ctaphid_channel_buffer_t *buffer) {
	buffer->cid = 0;
	buffer->cmd = 0;
	buffer->payload_length = 0;
	buffer->next_seq = 0;
	buffer->offset = 0;
}

static ctaphid_process_packet_result_t copy_payload_to_buffer(
	ctaphid_channel_buffer_t *buffer,
	const uint8_t *packet_payload,
	size_t packet_payload_size
) {
	assert(buffer->payload_length >= buffer->offset);
	size_t remaining_size = buffer->payload_length - buffer->offset;

	size_t copy_size = min(packet_payload_size, remaining_size);

	assert(buffer->offset + copy_size <= sizeof(buffer->payload));
	memcpy(&buffer->payload[buffer->offset], packet_payload, copy_size);
	buffer->offset += copy_size;

	if (buffer->offset == buffer->payload_length) {
		debug_log(green("  request message ready") nl);
		return CTAPHID_RESULT_MESSAGE;
	}

	debug_log("  buffered" nl);
	assert(buffer->offset < buffer->payload_length);
	return CTAPHID_RESULT_BUFFERING;
}

static inline bool is_initialization_packet(const ctaphid_packet_t *packet) {
	return packet->pkt.init.cmd & CTAPHID_PACKET_TYPE_INIT;
}

static inline bool is_continuation_packet(const ctaphid_packet_t *packet) {
	return !is_initialization_packet(packet);
}

void ctaphid_init(
	ctaphid_state_t *state
) {
	debug_log("ctaphid_init" nl);
	state->highest_allocated_cid = 0;
	reset_buffer(&state->buffer);
}

static inline bool is_idle(ctaphid_channel_buffer_t *buffer) {
	return buffer->cid == 0;
}

static inline bool is_complete_message(ctaphid_channel_buffer_t *buffer, uint8_t cmd) {
	return buffer->cmd == cmd && buffer->offset == buffer->payload_length;
}

static inline bool is_incomplete_message(ctaphid_channel_buffer_t *buffer) {
	return buffer->offset < buffer->payload_length;
}

/**
 * Updates the CTAPHID state by processing a CTAPHID packet (a HID report)
 */
ctaphid_process_packet_result_t ctaphid_process_packet(
	ctaphid_state_t *state,
	const ctaphid_packet_t *packet,
	uint8_t *error_code
) {
	ctaphid_channel_buffer_t *buffer = &state->buffer;

	if (is_initialization_packet(packet)) {
		debug_log(
			"ctaphid_process_packet"
			" cid=0x%08" PRIx32 " "
			cyan("initialization")
			" cmd=0x%02" wPRIx8
			" payload length=%" PRIu16 nl,
			packet->cid,
			packet->pkt.init.cmd,
			lion_ntohs(packet->pkt.init.bcnt)
		);
	} else {
		debug_log(
			"ctaphid_process_packet"
			" cid=0x%08" PRIx32 " "
			magenta("continuation")
			" seq=0x%02" wPRIx8 nl,
			packet->cid,
			packet->pkt.cont.seq
		);
	}

	// validate channel id
	if (packet->cid == 0 || packet->cid > state->highest_allocated_cid) {
		if (packet->cid == CTAPHID_BROADCAST_CID && packet->pkt.init.cmd == CTAPHID_INIT) {
			// The special CTAPHID_BROADCAST_CID value is only allowed with the CTAPHID_INIT command.
			// Note that packet->pkt.init.cmd == CTAPHID_INIT implies is_initialization_packet(packet) == true
			// (since we defined CTAPHID_INIT as (CTAPHID_PACKET_TYPE_INIT | 0x06)).
		} else {
			debug_log(red("  error: invalid channel") nl);
			*error_code = CTAP1_ERR_INVALID_CHANNEL;
			return CTAPHID_RESULT_ERROR;
		}
	}

	// See 11.2.5. Arbitration

	if (is_initialization_packet(packet)) {

		// special handling for 11.2.9.1.5. CTAPHID_CANCEL (0x11)
		if (packet->pkt.init.cmd == CTAPHID_CANCEL) {

			// validate the payload length (for CTAPHID_CANCEL it must be 0)
			if (lion_ntohs(packet->pkt.init.bcnt) != 0) {
				*error_code = CTAP1_ERR_INVALID_LENGTH;
				return CTAPHID_RESULT_ERROR;
			}

			// cancel if there is an ongoing CTAPHID_CBOR with the matching channel id
			if (packet->cid == buffer->cid && is_complete_message(buffer, CTAPHID_CBOR)) {
				return CTAPHID_RESULT_CANCEL;
			}

			// A CTAPHID_CANCEL received while no CTAPHID_CBOR request is being processed,
			// or on a non-active CID SHALL be ignored by the authenticator.
			debug_log(red("  ignored CTAPHID_CANCEL") nl);
			return CTAPHID_RESULT_IGNORED;

		}

		// special handling for 11.2.9.1.3. CTAPHID_INIT (0x06)
		if (packet->pkt.init.cmd == CTAPHID_INIT) {

			// validate the payload length (for CTAPHID_INIT must be 8)
			if (lion_ntohs(packet->pkt.init.bcnt) != 8) {
				*error_code = CTAP1_ERR_INVALID_LENGTH;
				return CTAPHID_RESULT_ERROR;
			}

			// If sent on the broadcast CID, it requests the device to allocate
			// a unique 32-bit channel identifier (CID) that can be used by the
			// requesting application during its lifetime.
			// The device then responds with the newly allocated channel in the response,
			// using the broadcast channel.
			if (packet->cid == CTAPHID_BROADCAST_CID) {
				return CTAPHID_RESULT_ALLOCATE_CHANNEL;
			}

			// If sent on an allocated CID, it synchronizes a channel, discarding the current transaction,
			// buffers and state as quickly as possible. It will then be ready for a new transaction.
			// The device then responds with the CID of the channel it received the INIT on, using that channel.
			// Note that, at this point, we know for sure that the packet cid is valid (allocated)
			// (thanks to the invalid channel check above).
			assert(packet->cid != 0 && packet->cid <= state->highest_allocated_cid);
			// 11.2.5.3. Transaction abort and re-synchronization
			//   If the device detects an INIT command during a transaction
			//   that has the same channel id as the active transaction,
			//   the transaction is aborted (if possible) and all buffered data flushed (if any).
			// Note that "if possible" translates (in our codebase) to is_incomplete_message(buffer)
			// because if the message is already complete, it means that it has been completed
			// in the previous invocation of ctaphid_process_packet() and therefore the CTAP layer
			// might have already started processing it.
			if (packet->cid == buffer->cid && is_incomplete_message(buffer)) {
				reset_buffer(buffer);
			}
			return CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE;

		}

		// 1.2.5.1. Transaction atomicity, idle and busy states
		//   The application channel that manages to get through the first **initialization packet**
		//   when the device is in **idle state** will keep the device locked for other channels
		//   until the last packet of the response message has been received or the transaction is aborted.

		// validate the payload length
		if (lion_ntohs(packet->pkt.init.bcnt) > sizeof(buffer->payload)) {
			debug_log(red("  error: payload length exceeded sizeof(buffer->payload)") nl);
			*error_code = CTAP1_ERR_INVALID_LENGTH;
			return CTAPHID_RESULT_ERROR;
		}

		if (!is_idle(buffer)) {
			debug_log(red("  error: init packet while channel busy") nl);
			*error_code = CTAP1_ERR_CHANNEL_BUSY;
			return CTAPHID_RESULT_ERROR;
		}

		assert(packet->cid != 0 && packet->cid <= state->highest_allocated_cid);
		buffer->cid = packet->cid;
		assert(packet->pkt.init.cmd != CTAPHID_CANCEL && packet->pkt.init.cmd != CTAPHID_INIT);
		buffer->cmd = packet->pkt.init.cmd;
		buffer->payload_length = lion_ntohs(packet->pkt.init.bcnt);
		buffer->next_seq = 0;
		buffer->offset = 0;
		return copy_payload_to_buffer(buffer, packet->pkt.init.payload, CTAPHID_PACKET_INIT_PAYLOAD_SIZE);

	}

	assert(is_continuation_packet(packet));

	if (buffer->cid != packet->cid) {
		// 11.2.5.4. Packet sequencing
		// Spurious continuation packets appearing without a prior initialization packet will be ignored.
		debug_log(red("  spurious continuation packet ignored") nl);
		return CTAPHID_RESULT_IGNORED;
	}

	assert(buffer->cid == packet->cid);
	assert(buffer->cmd != 0);
	assert(buffer->payload_length != 0);
	if (buffer->next_seq != packet->pkt.cont.seq) {
		*error_code = CTAP1_ERR_INVALID_SEQ;
		debug_log(
			red("  invalid seq: expected=%" wPRIu8 " got=%" wPRIu8) nl,
			buffer->next_seq, packet->pkt.cont.seq
		);
		return CTAPHID_RESULT_ERROR;
	}
	buffer->next_seq++;
	return copy_payload_to_buffer(buffer, packet->pkt.cont.payload, CTAPHID_PACKET_CONT_PAYLOAD_SIZE);

}
