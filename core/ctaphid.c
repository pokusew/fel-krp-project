#include "ctaphid.h"
#include "utils.h"
#include <string.h>
#include <stdbool.h>
#include "lionkey_config.h"

/**
 * Allocates a channel ID for a new channel
 *
 * The current implementation allocates Channel IDs (CIDs)'in ascending order
 * starting with 1, 2, 3, ... (0xFFFFFFFF - 1).
 *
 * The value 0 is a reserved value and if returned y this function,
 * it indicates an error (all possible CIDs allocated).
 *
 * The value 0xFFFFFFFF is a reserved value (CTAPHID_BROADCAST_CID) and it is never returned by this function.
 *
 * @param state
 * @return a valid channel ID or 0 when there is no channel ID left
 *         (i.e., when we already allocated 2^32 - 2 channels are there are no numbers left)
 */
uint32_t ctaphid_allocate_channel(ctaphid_state_t *state) {
	if (state->highest_allocated_cid + 1 == CTAPHID_BROADCAST_CID) {
		return 0;
	}
	return ++state->highest_allocated_cid;
}

void ctaphid_create_init_packet(
	ctaphid_packet_t *packet,
	uint32_t cid,
	uint8_t cmd,
	size_t payload_length
) {
	assert((cmd & 0x80) == 0x80);
	assert(payload_length <= CTAPHID_MAX_PAYLOAD_LENGTH);
	assert(payload_length <= 0xFFFF);
	memset(packet, 0, sizeof(ctaphid_packet_t));
	packet->cid = cid;
	packet->pkt.init.cmd = cmd;
	packet->pkt.init.bcnt = lion_htons(payload_length);
}

void ctaphid_create_error_packet(ctaphid_packet_t *packet, uint32_t cid, uint8_t error_code) {
	ctaphid_create_init_packet(packet, cid, CTAPHID_ERROR, 1);
	packet->pkt.init.payload[0] = error_code;
}

void ctaphid_create_ctaphid_init_response_packet(
	ctaphid_packet_t *packet,
	const uint8_t *nonce,
	uint32_t transport_cid,
	uint32_t response_cid
) {
	ctaphid_create_init_packet(
		packet,
		transport_cid,
		CTAPHID_INIT,
		sizeof(ctaphid_init_response_payload_t)
	);
	ctaphid_init_response_payload_t *init_res = (ctaphid_init_response_payload_t *) packet->pkt.init.payload;
	memcpy(init_res->nonce, nonce, sizeof(init_res->nonce));
	init_res->cid = response_cid;
	init_res->protocol_version = CTAPHID_PROTOCOL_VERSION;
	init_res->version_major = LIONKEY_CONFIG_CTAPHID_INIT_VERSION_MAJOR;
	init_res->version_minor = LIONKEY_CONFIG_CTAPHID_INIT_VERSION_MINOR;
	init_res->version_build = LIONKEY_CONFIG_CTAPHID_INIT_VERSION_BUILD;
	init_res->capabilities = LIONKEY_CONFIG_CTAPHID_CAPABILITY;
}

void ctaphid_message_to_packets(
	uint32_t cid,
	uint8_t cmd,
	size_t payload_length,
	const uint8_t *payload,
	ctap_packet_handler_t on_packet,
	void *on_packet_ctx
) {
	assert(payload_length <= CTAPHID_MAX_PAYLOAD_LENGTH);
	assert(payload_length <= 0xFFFF);
	assert(payload_length == 0 || payload != NULL);
	assert(on_packet != NULL);

	ctaphid_packet_t packet;

	// 11.2.4. Message and packet structure
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure

	// init packet
	// note that ctaphid_create_init_packet() fills the whole packet with zeros (including the payload)
	ctaphid_create_init_packet(
		&packet,
		cid,
		cmd,
		payload_length
	);
	// fast path
	if (payload_length == 0) {
		dump_hex((const uint8_t *) &packet, sizeof(packet));
		on_packet(&packet, on_packet_ctx);
		return;
	}
	const size_t init_packet_data_size = min(payload_length, CTAPHID_PACKET_INIT_PAYLOAD_SIZE);
	memcpy(&packet.pkt.init.payload, payload, init_packet_data_size);
	// no need to zero the rest of the payload (ctaphid_create_init_packet() already ensures that)
	dump_hex((const uint8_t *) &packet, sizeof(packet));
	on_packet(&packet, on_packet_ctx);

	// continuation packets (if necessary)
	size_t offset = init_packet_data_size;
	size_t remaining_data_size = payload_length - init_packet_data_size;
	uint8_t seq = 0;
	while (remaining_data_size > 0) {

		packet.cid = cid;
		packet.pkt.cont.seq = seq;
		size_t payload_size = min(remaining_data_size, CTAPHID_PACKET_CONT_PAYLOAD_SIZE);
		memcpy(packet.pkt.cont.payload, &payload[offset], payload_size);
		if (payload_size < CTAPHID_PACKET_CONT_PAYLOAD_SIZE) {
			memset(&packet.pkt.cont.payload[payload_size], 0, CTAPHID_PACKET_CONT_PAYLOAD_SIZE - payload_size);
		}
		dump_hex((const uint8_t *) &packet, sizeof(packet));
		on_packet(&packet, on_packet_ctx);

		assert(remaining_data_size >= payload_size);
		remaining_data_size -= payload_size;
		offset += payload_size;
		++seq;

	}

}

static inline bool is_idle(const ctaphid_channel_buffer_t *buffer) {
	return buffer->cid == 0;
}

static inline bool is_complete_message(const ctaphid_channel_buffer_t *buffer) {
	return buffer->offset == buffer->payload_length;
}

static inline bool is_complete_message_cmd(const ctaphid_channel_buffer_t *buffer, const uint8_t cmd) {
	return buffer->cmd == cmd && is_complete_message(buffer);
}

static inline bool is_incomplete_message(const ctaphid_channel_buffer_t *buffer) {
	return buffer->offset < buffer->payload_length;
}

bool ctaphid_is_idle(const ctaphid_state_t *state) {
	const ctaphid_channel_buffer_t *buffer = &state->buffer;
	assert(buffer->cid != CTAPHID_BROADCAST_CID);
	return is_idle(buffer);
}

bool ctaphid_has_complete_message_ready(const ctaphid_state_t *state) {
	const ctaphid_channel_buffer_t *buffer = &state->buffer;
	assert(buffer->cid != CTAPHID_BROADCAST_CID);
	if (is_idle(buffer)) {
		return false;
	}
	assert(buffer->cmd != 0);
	return is_complete_message(buffer);
}

static void reset_buffer(ctaphid_channel_buffer_t *buffer) {
	buffer->cid = 0;
	buffer->cmd = 0;
	buffer->cancel = false;
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

	if (is_complete_message(buffer)) {
		debug_log(green("  request message ready") nl);
		return CTAPHID_RESULT_MESSAGE;
	}

	debug_log("  buffered" nl);
	assert(is_incomplete_message(buffer));
	return CTAPHID_RESULT_BUFFERING;
}

static inline bool is_initialization_packet(const ctaphid_packet_t *packet) {
	return packet->pkt.init.cmd & CTAPHID_PACKET_TYPE_INIT;
}

static inline bool is_continuation_packet(const ctaphid_packet_t *packet) {
	return !is_initialization_packet(packet);
}

void ctaphid_init(ctaphid_state_t *state) {
	debug_log("ctaphid_init" nl);
	state->highest_allocated_cid = 0;
	reset_buffer(&state->buffer);
}

void ctaphid_reset_to_idle(ctaphid_state_t *state) {
	debug_log("ctaphid_reset_to_idle" nl);
	reset_buffer(&state->buffer);
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

	// TODO: Implement channel timeout:
	//   Reset the buffer via ctaphid_reset_to_idle() when no packet is received within X seconds
	//   on the current busy channel (buffer holds an incomplete message).
	//   This way other channels get chance to communicate and a stuck channel cannot block the communication.
	//   Once the buffer is reset, we can start receiving (assembling) a new message from any valid (allocated) channel.

	if (is_initialization_packet(packet)) {
		debug_log(
			"ctaphid_process_packet"
			" cid=0x%08" PRIx32 " "
			cyan("initialization")
			" cmd=0x%02" wPRIx8
			" payload_length=%" PRIu16 nl,
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
			if (packet->cid == buffer->cid && is_complete_message_cmd(buffer, CTAPHID_CBOR)) {
				buffer->cancel = true;
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
		buffer->cancel = false;
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

#if LIONKEY_DEBUG_LEVEL > 0
const char *const debug_str_ctaphid_process_packet_result[] = {
	[CTAPHID_RESULT_ERROR] = "CTAPHID_RESULT_ERROR",
	[CTAPHID_RESULT_IGNORED] = "CTAPHID_RESULT_IGNORED",
	[CTAPHID_RESULT_CANCEL] = "CTAPHID_RESULT_CANCEL",
	[CTAPHID_RESULT_ALLOCATE_CHANNEL] = "CTAPHID_RESULT_ALLOCATE_CHANNEL",
	[CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE] = "CTAPHID_RESULT_DISCARD_INCOMPLETE_MESSAGE",
	[CTAPHID_RESULT_BUFFERING] = "CTAPHID_RESULT_BUFFERING",
	[CTAPHID_RESULT_MESSAGE] = "CTAPHID_RESULT_MESSAGE",
};
#endif
