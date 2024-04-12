#include <stdio.h>
#include <string.h>

#include "ctaphid.h"
#include "util.h"
#include "log.h"
#include "utils.h"
#include "device.h"

#include APP_CONFIG

static void buffer_reset(ctaphid_channel_buffer_t *buffer);

#define ctaphid_write_buffer_init(x) memset(x, 0, sizeof(ctaphid_write_buffer_t))

static void ctaphid_write(ctaphid_write_buffer_t *wb, const uint8_t *data, size_t len);

void ctaphid_init(
	ctaphid_state_t *state,
	ctaphid_cbor_handler_t ctap_handler,
	void *ctap_handler_context
) {

	debug_log("ctaphid_init" nl);

	state->last_cid = 0;
	ll_init(&state->free_channels);
	ll_init(&state->used_channels);
	for (int idx = 0; idx < CTAPHID_NUM_CHANNELS; ++idx) {
		ctaphid_channel_t *channel = &state->channels[idx];
		channel->prev = NULL;
		channel->next = NULL;
		channel->cid = 0;
		channel->last_used = 0;
		channel->busy = false;
		ll_add_to_tail(&state->free_channels, (ll_entry_t *) channel);
	}

	buffer_reset(&state->buffer);

	state->ctap_handler = ctap_handler;
	state->ctap_handler_context = ctap_handler_context;

}

static uint32_t get_new_cid(ctaphid_state_t *state) {
	// simply increase the last assigned CID by 1 but skip the reserved CIDs
	do {
		state->last_cid++;
	} while (state->last_cid == 0 || state->last_cid == 0xffffffff);
	debug_log("get_new_cid cid = %08" PRIx32 nl, state->last_cid);
	return state->last_cid;
}

static bool add_cid(ctaphid_state_t *state, uint32_t cid) {

	debug_log("add_cid cid = %08" PRIx32 nl, cid);

	ctaphid_channel_t *channel = (ctaphid_channel_t *) ll_remove_from_head(&state->free_channels);

	if (channel == NULL) {
		// this means that all CTAPHID_NUM_CHANNELS are busy
		return false;
	}

	channel->cid = cid;
	channel->busy = true;
	channel->last_used = millis();

	ll_add_to_tail(&state->used_channels, (ll_entry_t *) channel);

	return true;

}

static ctaphid_channel_t *find_channel(ctaphid_state_t *state, uint32_t cid) {

	debug_log("find_channel cid = %08" PRIx32 nl, cid);

	ctaphid_channel_t *channel = (ctaphid_channel_t *) state->used_channels.head;

	while (channel != NULL) {
		if (channel->cid == cid) {
			return channel;
		}
		channel = channel->next;
	}

	return NULL;

}

static bool is_broadcast(const ctaphid_packet_t *pkt) {
	return (pkt->cid == CTAPHID_BROADCAST_CID);
}

static bool is_packet_type_initialization(const ctaphid_packet_t *pkt) {
	return pkt->pkt.init.cmd & TYPE_INIT;
}

static bool is_packet_type_continuation(const ctaphid_packet_t *pkt) {
	return !is_packet_type_initialization(pkt);
}

static bool buffer_packet(ctaphid_channel_buffer_t *buffer, ctaphid_packet_t *pkt) {

	if (is_packet_type_initialization(pkt)) {
		debug_log("buffer_packet initialization" nl);
		buffer->cid = pkt->cid;
		buffer->cmd = pkt->pkt.init.cmd;
		buffer->bcnt = ctaphid_payload_length(pkt);
		int pkt_len = (buffer->bcnt < CTAPHID_INIT_PAYLOAD_SIZE) ? buffer->bcnt : CTAPHID_INIT_PAYLOAD_SIZE;
		buffer->offset = pkt_len;
		buffer->seq = -1;
		// debug_log("  memcpy %p %p %d" nl, buffer->payload, pkt->pkt.init.payload, pkt_len);
		memcpy(buffer->payload, pkt->pkt.init.payload, pkt_len);
		return true;
	}

	debug_log("buffer_packet continuation" nl);
	buffer->seq++;
	if (buffer->seq != pkt->pkt.cont.seq) {
		debug_log("  SEQUENCE_ERROR" nl);
		return false;
	}
	int num_remaining_bytes = buffer->bcnt - buffer->offset;
	int pkt_len = (num_remaining_bytes < CTAPHID_CONT_PAYLOAD_SIZE) ? num_remaining_bytes : CTAPHID_CONT_PAYLOAD_SIZE;
	// debug_log("  memcpy %p %p %d" nl, buffer->payload + buffer->offset, pkt->pkt.cont.payload, pkt_len);
	memcpy(buffer->payload + buffer->offset, pkt->pkt.cont.payload, pkt_len);
	buffer->offset += pkt_len;
	return true;

}

static void buffer_reset(ctaphid_channel_buffer_t *buffer) {
	buffer->cid = 0;
	buffer->cmd = 0;
	buffer->bcnt = 0;
	buffer->seq = 0;
	buffer->offset = 0;
}

static int buffer_status(const ctaphid_channel_buffer_t *buffer) {
	if (buffer->bcnt == 0) {
		return EMPTY;
	} else if (buffer->offset == buffer->bcnt) {
		return BUFFERED;
	} else {
		return BUFFERING;
	}
}

/**
 * Buffer data and send in HID_MESSAGE_SIZE chunks,
 * if len == 0, FLUSH.
 */
static void ctaphid_write(ctaphid_write_buffer_t *wb, const uint8_t *data, size_t len) {
	if (data == NULL) {
		if (wb->offset == 0 && wb->bytes_written == 0) {
			memmove(wb->buf, &wb->cid, 4);
			wb->offset += 4;

			wb->buf[4] = wb->cmd;
			wb->buf[5] = (wb->bcnt & 0xff00) >> 8;
			wb->buf[6] = (wb->bcnt & 0xff) >> 0;
			wb->offset += 3;
		}

		if (wb->offset > 0) {
			memset(wb->buf + wb->offset, 0, HID_MESSAGE_SIZE - wb->offset);
			usbhid_send(wb->buf);
		}
		return;
	}
	for (size_t i = 0; i < len; ++i) {
		if (wb->offset == 0) {
			memmove(wb->buf, &wb->cid, 4);
			wb->offset += 4;

			if (wb->bytes_written == 0) {
				wb->buf[4] = wb->cmd;
				wb->buf[5] = (wb->bcnt & 0xff00) >> 8;
				wb->buf[6] = (wb->bcnt & 0xff) >> 0;
				wb->offset += 3;
			} else {
				wb->buf[4] = wb->seq++;
				wb->offset += 1;
			}
		}
		wb->buf[wb->offset++] = data[i];
		wb->bytes_written += 1;
		if (wb->offset == HID_MESSAGE_SIZE) {
			usbhid_send(wb->buf);
			wb->offset = 0;
		}
	}
}

static void ctaphid_send_error(ctaphid_state_t *state, uint32_t cid, uint8_t error) {

	state->wb.cid = cid;
	state->wb.cmd = CTAPHID_ERROR;
	state->wb.bcnt = 1;

	ctaphid_write(&state->wb, &error, 1);
	ctaphid_write(&state->wb, NULL, 0);

}

static void send_init_response(uint32_t old_cid, uint32_t new_cid, uint8_t *nonce) {
	ctaphid_init_response_payload_t init_resp;
	ctaphid_write_buffer_t wb;
	ctaphid_write_buffer_init(&wb);
	wb.cid = old_cid;
	wb.cmd = CTAPHID_INIT;
	wb.bcnt = 17;

	memmove(init_resp.nonce, nonce, 8);
	init_resp.cid = new_cid;
	init_resp.protocol_version = CTAPHID_PROTOCOL_VERSION;
	init_resp.version_major = 0; // ?
	init_resp.version_minor = 0; // ?
	init_resp.version_build = 0; // ?
	init_resp.capabilities = CTAP_CAPABILITIES;

	ctaphid_write(&wb, (uint8_t *) &init_resp, sizeof(ctaphid_init_response_payload_t));
	ctaphid_write(&wb, NULL, 0);
}

void ctaphid_check_timeouts(ctaphid_state_t *state) {

	ctaphid_channel_t *channel = (ctaphid_channel_t *) state->used_channels.head;

	while (channel != NULL) {
		if (channel->busy && ((millis() - channel->last_used) >= 750)) {
			printf1(TAG_HID, "TIMEOUT CID: %08" PRIx32 nl, channel->cid);
			ctaphid_send_error(state, channel->cid, CTAP1_ERR_TIMEOUT);
			channel->busy = false;
			if (channel->cid == state->buffer.cid) {
				buffer_reset(&state->buffer);
			}
		}
		channel = channel->next;
	}

}

void ctaphid_update_status(ctaphid_state_t *state, uint8_t status) {
	ctaphid_write_buffer_t wb;
	printf1(TAG_HID, "Send device update %d!" nl, status);
	ctaphid_write_buffer_init(&wb);

	wb.cid = state->buffer.cid;
	wb.cmd = CTAPHID_KEEPALIVE;
	wb.bcnt = 1;

	ctaphid_write(&wb, &status, 1);
	ctaphid_write(&wb, NULL, 0);
}

static ctap_buffer_state_t ctaphid_buffer_packet(
	ctaphid_state_t *state,
	ctaphid_packet_t *pkt,
	uint8_t *error_code
) {
	ctaphid_channel_buffer_t *buffer = &state->buffer;

	if (is_packet_type_initialization(pkt)) {
		debug_log(
			"ctaphid_buffer_packet " cyan("initialization") nl
			"  cid: 0x%08" PRIx32 nl
			"  cmd: 0x%02" wPRIx8 nl
			"  payload length: %" PRIu16 nl,
			pkt->cid,
			pkt->pkt.init.cmd,
			ctaphid_payload_length(pkt)
		);
	} else {
		debug_log(
			"ctaphid_buffer_packet " magenta("continuation") nl
			"  seq: %02" wPRIx8 " (%" wPRIu8 ")" nl,
			pkt->pkt.cont.seq,
			pkt->pkt.cont.seq
		);
	}

	if (pkt->cid == 0) {
		debug_log(red("error: invalid cid 0") nl);
		*error_code = CTAP1_ERR_INVALID_CHANNEL;
		return HID_ERROR;
	}

	if (is_packet_type_initialization(pkt)) {

		if (ctaphid_payload_length(pkt) > CTAPHID_BUFFER_SIZE) {
			debug_log(
				red("error: message payload length (%" PRIx16 ") exceeds buffer size (%" PRIx16 ")") nl,
				ctaphid_payload_length(pkt),
				CTAPHID_BUFFER_SIZE
			);
			*error_code = CTAP1_ERR_INVALID_LENGTH;
			return HID_ERROR;
		}

		// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
		if (pkt->pkt.init.cmd == CTAPHID_INIT) {

			if (ctaphid_payload_length(pkt) != 8) {
				debug_log(
					red("error: CTAPHID_INIT payload length (%" PRIx16 ") !== 8") nl,
					ctaphid_payload_length(pkt)
				);
				*error_code = CTAP1_ERR_INVALID_LENGTH;
				return HID_ERROR;
			}

			if (is_broadcast(pkt)) {
				// TODO: Is it allowed to assign a new CID to some client while other channel is busy?
				debug_log("adding a new cid" nl);
				uint32_t new_cid = get_new_cid(state);
				if (!add_cid(state, new_cid)) {
					debug_log(red("error: not enough memory for a new cid > returning CTAP1_ERR_CHANNEL_BUSY") nl);
					*error_code = CTAP1_ERR_CHANNEL_BUSY;
					return HID_ERROR;
				}
				send_init_response(CTAPHID_BROADCAST_CID, new_cid, pkt->pkt.init.payload);
				return HID_IGNORE;
			}

			ctaphid_channel_t *channel = find_channel(state, pkt->cid);

			if (channel == NULL) {
				// TODO: Theoretically we could add the CID as a new channel if the buffer is currently empty.
				debug_log(red("error: invalid channel, cid 0x%08" PRIx32 " not found") nl, pkt->cid);
				*error_code = CTAP1_ERR_INVALID_CHANNEL;
				return HID_ERROR;
			}

			if (buffer->cid == channel->cid) {
				// CTAPHID_INIT If sent on an allocated CID, it synchronizes a channel,
				// discarding the current transaction, buffers and state as quickly as possible.
				// It will then be ready for a new transaction.
				// The authenticator then responds with the CID of the channel it received the INIT on,
				// using that channel.
				debug_log("CTAPHID_INIT used for resynchronization" nl);
				// TODO: ctap_reset_state might be needed per spec?
				buffer_reset(buffer);
				send_init_response(channel->cid, channel->cid, pkt->pkt.init.payload);
				return HID_IGNORE;
			}

			debug_log(red("error: resynchronization CTAPHID_INIT but busy with different channel") nl);
			*error_code = CTAP1_ERR_CHANNEL_BUSY;
			return HID_ERROR;

		}

		ctaphid_channel_t *channel = find_channel(state, pkt->cid);

		if (channel == NULL) {
			// TODO: Theoretically we could add the CID as a new channel if the buffer is currently empty.
			debug_log(red("error: invalid channel, cid 0x%08" PRIx32 " not found") nl, pkt->cid);
			*error_code = CTAP1_ERR_INVALID_CHANNEL;
			return HID_ERROR;
		}

		if (buffer_status(buffer) == EMPTY) {
			if (!buffer_packet(buffer, pkt)) {
				debug_log("error: unexpected buffer_packet sequence error" nl);
				*error_code = CTAP1_ERR_INVALID_SEQ;
				return HID_ERROR;
			}
			return buffer_status(buffer);
		}

		debug_log(
			red("error: initialization packet from cid 0x%08" PRIx32 " but BUSY with cid 0x%08" PRIx32) nl,
			pkt->cid,
			buffer->cid
		);
		*error_code = CTAP1_ERR_CHANNEL_BUSY;
		return HID_ERROR;

	}

	assert(is_packet_type_continuation(pkt));

	if (pkt->cid == CTAPHID_BROADCAST_CID) {
		debug_log(red("error: continuation packet with broadcast cid") nl);
		*error_code = CTAP1_ERR_INVALID_CHANNEL;
		return HID_ERROR;
	}

	ctaphid_channel_t *channel = find_channel(state, pkt->cid);

	if (channel == NULL) {
		debug_log(red("error: invalid channel, cid 0x%08" PRIx32 " not found") nl, pkt->cid);
		*error_code = CTAP1_ERR_INVALID_CHANNEL;
		return HID_ERROR;
	}

	if (pkt->cid != buffer->cid) {
		debug_log(
			red("error: packet from cid 0x%08" PRIx32 " but other cid 0x%08" PRIx32 " is busy (buffering)") nl,
			pkt->cid,
			buffer->cid
		);
		*error_code = CTAP1_ERR_CHANNEL_BUSY;
		return HID_ERROR;
	}

	if (!buffer_packet(buffer, pkt)) {
		debug_log("error: buffer_packet sequence error" nl);
		*error_code = CTAP1_ERR_INVALID_SEQ;
		return HID_ERROR;
	}

	return buffer_status(buffer);

}


uint8_t ctaphid_handle_packet(ctaphid_state_t *state, ctaphid_packet_t *pkt) {

	debug_log("ctaphid_handle_packet" nl);

	millis_t handling_start = millis();
	millis_t writeback_start;
	uint8_t response_status_code = 0;

	int buf_status = ctaphid_buffer_packet(state, pkt, &response_status_code);
	ctaphid_write_buffer_init(&state->wb);

	if (buf_status == HID_IGNORE) {
		debug_log("buf_status == HID_IGNORE" nl);
		return 0;
	}

	if (buf_status == HID_ERROR) {
		debug_log(red("error buf_status == HID_ERROR, response_status_code = %02" wPRIx8) nl, response_status_code);
		if (response_status_code == CTAP1_ERR_INVALID_SEQ) {
			buffer_reset(&state->buffer);
		}
		ctaphid_send_error(state, pkt->cid, response_status_code);
		return 0;
	}

	if (buf_status == BUFFERING) {
		debug_log("buf_status == BUFFERING" nl);
		return 0;
	}

	assert(buf_status == BUFFERED);
	// CTAPHID_INIT should be handled by ctaphid_buffer_packet
	assert(state->buffer.cmd != CTAPHID_INIT);

	// reply on the same channel to which the request came
	// a response to the request has the same command id
	state->wb.cid = state->buffer.cid;
	state->wb.cmd = state->buffer.cmd;

	switch (state->buffer.cmd) {

		case CTAPHID_PING:
			info_log(cyan("CTAPHID_PING") nl);

			state->wb.bcnt = state->buffer.bcnt;
			writeback_start = millis();
			ctaphid_write(&state->wb, state->buffer.payload, state->wb.bcnt);
			ctaphid_write(&state->wb, NULL, 0);
			info_log("PING writeback took %" PRId32 " ms" nl, timestamp_diff(writeback_start));

			break;

		case CTAPHID_WINK:
			info_log(cyan("CTAPHID_WINK") nl);

			device_wink();

			ctaphid_write(&state->wb, NULL, 0);

			break;

		case CTAPHID_CBOR:
			info_log(cyan("CTAPHID_CBOR") nl);

			if (state->buffer.bcnt == 0) {
				info_log(red("error: invalid payload length 0 for CTAPHID_CBOR message") nl);
				ctaphid_send_error(state, state->buffer.cid, CTAP1_ERR_INVALID_LENGTH);
				return 0;
			}

			uint16_t response_data_length;
			uint8_t *response_data;

			state->ctap_handler(
				state->ctap_handler_context,
				state->buffer.bcnt,
				state->buffer.payload,
				&response_status_code,
				&response_data_length,
				&response_data
			);

			state->wb.bcnt = response_data_length + 1;

			ctaphid_write(&state->wb, &response_status_code, 1);
			ctaphid_write(&state->wb, response_data, response_data_length);
			ctaphid_write(&state->wb, NULL, 0);
			info_log(cyan("CBOR response generated in %" PRId32 " ms") nl, timestamp_diff(handling_start));

			break;

		case CTAPHID_CANCEL:
			info_log(cyan("CTAPHID_CANCEL") nl);
			// TODO: Implement CTAPHID_CANCEL.
			//  See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-cancel
			break;

		default:
			info_log(red("error: unimplemented CTAPHID cmd: %02" wPRIx8), state->buffer.cmd);
			ctaphid_send_error(state, state->buffer.cid, CTAP1_ERR_INVALID_COMMAND);

	}

	buffer_reset(&state->buffer);

	return 0;

}
