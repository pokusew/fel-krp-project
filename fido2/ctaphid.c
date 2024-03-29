#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device.h"
#include "ctaphid.h"
#include "ctap.h"
#include "util.h"
#include "log.h"
#include "utils.h"

#include APP_CONFIG

typedef enum {
	IDLE = 0,
	HANDLING_REQUEST,
} CTAP_STATE;

typedef enum {
	EMPTY = 0,
	BUFFERING,
	BUFFERED,
	HID_ERROR,
	HID_IGNORE,
} CTAP_BUFFER_STATE;


typedef struct {
	uint8_t cmd;
	uint32_t cid;
	uint16_t bcnt;
	int offset;
	int bytes_written;
	uint8_t seq;
	uint8_t buf[HID_MESSAGE_SIZE];
} CTAPHID_WRITE_BUFFER;

struct CID {
	uint32_t cid;
	uint64_t last_used;
	uint8_t busy;
	uint8_t last_cmd;
};


#define SUCCESS         0
#define SEQUENCE_ERROR  1

static int state;
static struct CID CIDS[10];
#define CID_MAX (sizeof(CIDS)/sizeof(struct CID))

static uint64_t active_cid_timestamp;

static uint8_t ctap_buffer[CTAPHID_BUFFER_SIZE];
static uint32_t ctap_buffer_cid;
static int ctap_buffer_cmd;
static uint16_t ctap_buffer_bcnt;
static int ctap_buffer_offset;
static int ctap_packet_seq;

static void buffer_reset();

#define CTAPHID_WRITE_INIT      0x01
#define CTAPHID_WRITE_FLUSH     0x02
#define CTAPHID_WRITE_RESET     0x04

#define     ctaphid_write_buffer_init(x)    memset(x,0,sizeof(CTAPHID_WRITE_BUFFER))

static void ctaphid_write(CTAPHID_WRITE_BUFFER *wb, void *_data, int len);

void ctaphid_init() {
	debug_log("ctaphid_init" nl);
	state = IDLE;
	buffer_reset();
	//ctap_reset_state();
}

static uint32_t get_new_cid() {
	static uint32_t cid = 1;
	do {
		cid++;
	} while (cid == 0 || cid == 0xffffffff);
	debug_log("get_new_cid cid = %08" PRIx32 nl, cid);
	return cid;
}

static int8_t add_cid(uint32_t cid) {
	debug_log("add_cid cid = %08" PRIx32 nl, cid);
	for (uint32_t i = 0; i < CID_MAX - 1; i++) {
		if (!CIDS[i].busy) {
			CIDS[i].cid = cid;
			CIDS[i].busy = 1;
			CIDS[i].last_used = millis();
			return 0;
		}
	}
	return -1;
}

static int8_t cid_exists(uint32_t cid) {
	debug_log("cid_exists cid = %08" PRIx32 nl, cid);
	for (uint32_t i = 0; i < CID_MAX - 1; i++) {
		if (CIDS[i].cid == cid) {
			return 1;
		}
	}
	return 0;
}

static int8_t cid_refresh(uint32_t cid) {
	debug_log("cid_refresh cid = %08" PRIx32 nl, cid);
	for (uint32_t i = 0; i < CID_MAX - 1; i++) {
		if (CIDS[i].cid == cid) {
			CIDS[i].last_used = millis();
			CIDS[i].busy = 1;
			return 0;
		}
	}
	return -1;
}

static int8_t cid_del(uint32_t cid) {
	debug_log("cid_del cid = %08" PRIx32 nl, cid);
	for (uint32_t i = 0; i < CID_MAX - 1; i++) {
		if (CIDS[i].cid == cid) {
			CIDS[i].busy = 0;
			return 0;
		}
	}
	return -1;
}

static int is_broadcast(CTAPHID_PACKET *pkt) {
	return (pkt->cid == CTAPHID_BROADCAST_CID);
}

static int is_init_pkt(CTAPHID_PACKET *pkt) {
	return (pkt->pkt.init.cmd == CTAPHID_INIT);
}

static int is_cont_pkt(CTAPHID_PACKET *pkt) {
	return !(pkt->pkt.init.cmd & TYPE_INIT);
}


static int buffer_packet(CTAPHID_PACKET *pkt) {
	if (pkt->pkt.init.cmd & TYPE_INIT) {
		debug_log("buffer_packet INIT" nl);
		ctap_buffer_bcnt = ctaphid_packet_len(pkt);
		int pkt_len = (ctap_buffer_bcnt < CTAPHID_INIT_PAYLOAD_SIZE) ? ctap_buffer_bcnt : CTAPHID_INIT_PAYLOAD_SIZE;
		ctap_buffer_cmd = pkt->pkt.init.cmd;
		ctap_buffer_cid = pkt->cid;
		ctap_buffer_offset = pkt_len;
		ctap_packet_seq = -1;
		// debug_log("memmove init %p %p %d" nl, ctap_buffer, pkt->pkt.init.payload, pkt_len);
		memcpy(ctap_buffer, pkt->pkt.init.payload, pkt_len);
	} else {
		debug_log("buffer_packet CONT" nl);
		int leftover = ctap_buffer_bcnt - ctap_buffer_offset;
		int diff = leftover - CTAPHID_CONT_PAYLOAD_SIZE;
		ctap_packet_seq++;
		if (ctap_packet_seq != pkt->pkt.cont.seq) {
			return SEQUENCE_ERROR;
		}

		if (diff <= 0) {
			// only move the leftover amount
			// debug_log(
			// 	"memmove leftover %p %p %d" nl,
			// 	ctap_buffer + ctap_buffer_offset, pkt->pkt.init.payload, leftover
			// );
			memcpy(ctap_buffer + ctap_buffer_offset, pkt->pkt.cont.payload, leftover);
			ctap_buffer_offset += leftover;
		} else {
			// debug_log(
			// 	"memmove cont_payload_size %p %p %d" nl,
			// 	ctap_buffer + ctap_buffer_offset, pkt->pkt.init.payload,
			// 	CTAPHID_CONT_PAYLOAD_SIZE
			// );
			memcpy(ctap_buffer + ctap_buffer_offset, pkt->pkt.cont.payload, CTAPHID_CONT_PAYLOAD_SIZE);
			ctap_buffer_offset += CTAPHID_CONT_PAYLOAD_SIZE;
		}
	}
	return SUCCESS;
}

static void buffer_reset() {
	ctap_buffer_bcnt = 0;
	ctap_buffer_offset = 0;
	ctap_packet_seq = 0;
	ctap_buffer_cid = 0;
}

static int buffer_status() {
	if (ctap_buffer_bcnt == 0) {
		return EMPTY;
	} else if (ctap_buffer_offset == ctap_buffer_bcnt) {
		return BUFFERED;
	} else {
		return BUFFERING;
	}
}

static int buffer_cmd() {
	return ctap_buffer_cmd;
}

static uint32_t buffer_cid() {
	return ctap_buffer_cid;
}


static int buffer_len() {
	return ctap_buffer_bcnt;
}

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
static void ctaphid_write(CTAPHID_WRITE_BUFFER *wb, void *_data, int len) {
	uint8_t *data = (uint8_t *) _data;
	if (_data == NULL) {
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
	int i;
	for (i = 0; i < len; i++) {
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


static void ctaphid_send_error(uint32_t cid, uint8_t error) {
	CTAPHID_WRITE_BUFFER wb;
	ctaphid_write_buffer_init(&wb);

	wb.cid = cid;
	wb.cmd = CTAPHID_ERROR;
	wb.bcnt = 1;

	ctaphid_write(&wb, &error, 1);
	ctaphid_write(&wb, NULL, 0);
}

static void send_init_response(uint32_t oldcid, uint32_t newcid, uint8_t *nonce) {
	CTAPHID_INIT_RESPONSE init_resp;
	CTAPHID_WRITE_BUFFER wb;
	ctaphid_write_buffer_init(&wb);
	wb.cid = oldcid;
	wb.cmd = CTAPHID_INIT;
	wb.bcnt = 17;

	memmove(init_resp.nonce, nonce, 8);
	init_resp.cid = newcid;
	init_resp.protocol_version = CTAPHID_PROTOCOL_VERSION;
	init_resp.version_major = 0;//?
	init_resp.version_minor = 0;//?
	init_resp.version_build = 0;//?
	init_resp.capabilities = CTAP_CAPABILITIES;

	ctaphid_write(&wb, &init_resp, sizeof(CTAPHID_INIT_RESPONSE));
	ctaphid_write(&wb, NULL, 0);
}


void ctaphid_check_timeouts() {
	for (uint8_t i = 0; i < CID_MAX; i++) {
		if (CIDS[i].busy && ((millis() - CIDS[i].last_used) >= 750)) {
			printf1(TAG_HID, "TIMEOUT CID: %08" PRIx32 nl, CIDS[i].cid);
			ctaphid_send_error(CIDS[i].cid, CTAP1_ERR_TIMEOUT);
			CIDS[i].busy = 0;
			if (CIDS[i].cid == buffer_cid()) {
				buffer_reset();
			}
			// memset(CIDS + i, 0, sizeof(struct CID));
		}
	}
}

void ctaphid_update_status(int8_t status) {
	CTAPHID_WRITE_BUFFER wb;
	printf1(TAG_HID, "Send device update %d!" nl, status);
	ctaphid_write_buffer_init(&wb);

	wb.cid = buffer_cid();
	wb.cmd = CTAPHID_KEEPALIVE;
	wb.bcnt = 1;

	ctaphid_write(&wb, &status, 1);
	ctaphid_write(&wb, NULL, 0);
}

static int ctaphid_buffer_packet(uint8_t *pkt_raw, uint8_t *cmd, uint32_t *cid, int *len) {
	CTAPHID_PACKET *pkt = (CTAPHID_PACKET *) (pkt_raw);

	printf1(TAG_HID, "ctaphid_buffer_packet" nl);
	printf1(TAG_HID, "  CID: 0x%08" PRIx32 nl, pkt->cid);
	printf1(TAG_HID, "  cmd: 0x%02" wPRIx8 nl, pkt->pkt.init.cmd);
	if (!is_cont_pkt(pkt)) {
		printf1(TAG_HID, "  length: %d" nl, ctaphid_packet_len(pkt));
	}

	int ret;
	uint32_t oldcid;
	uint32_t newcid;

	*cid = pkt->cid;

	if (is_init_pkt(pkt)) {

		if (ctaphid_packet_len(pkt) != 8) {
			printf2(TAG_ERR, "Error, invalid length field for init packet" nl);
			*cmd = CTAP1_ERR_INVALID_LENGTH;
			return HID_ERROR;
		}

		if (pkt->cid == 0) {
			printf2(TAG_ERR, "Error, invalid cid 0" nl);
			*cmd = CTAP1_ERR_INVALID_CHANNEL;
			return HID_ERROR;
		}

		ctaphid_init();
		if (is_broadcast(pkt)) {
			// Check if any existing cids are busy first ?
			printf1(TAG_HID, "adding a new cid" nl);
			oldcid = CTAPHID_BROADCAST_CID;
			newcid = get_new_cid();
			ret = add_cid(newcid);
			// handle init here
		} else {
			printf1(TAG_HID, "synchronizing to cid" nl);
			oldcid = pkt->cid;
			newcid = pkt->cid;
			if (cid_exists(newcid)) {
				ret = cid_refresh(newcid);
			} else {
				ret = add_cid(newcid);
			}
		}
		if (ret == -1) {
			printf2(TAG_ERR, "Error, not enough memory for new CID.  return BUSY." nl);
			*cmd = CTAP1_ERR_CHANNEL_BUSY;
			return HID_ERROR;
		}
		send_init_response(oldcid, newcid, pkt->pkt.init.payload);
		cid_del(newcid);

		return HID_IGNORE;
	} else {

		if (pkt->cid == CTAPHID_BROADCAST_CID) {
			*cmd = CTAP1_ERR_INVALID_CHANNEL;
			return HID_ERROR;
		}

		if (!cid_exists(pkt->cid) && !is_cont_pkt(pkt)) {
			if (buffer_status() == EMPTY) {
				add_cid(pkt->cid);
			}
		}

		if (cid_exists(pkt->cid)) {
			if (buffer_status() == BUFFERING) {
				if (pkt->cid == buffer_cid() && !is_cont_pkt(pkt)) {
					printf2(TAG_ERR, "INVALID_SEQ" nl);
					printf2(TAG_ERR, "Have %d/%d bytes" nl, ctap_buffer_offset, ctap_buffer_bcnt);
					*cmd = CTAP1_ERR_INVALID_SEQ;
					return HID_ERROR;
				} else if (pkt->cid != buffer_cid()) {
					if (!is_cont_pkt(pkt)) {
						printf2(TAG_ERR, "BUSY with %08" PRIx32 nl, buffer_cid());
						*cmd = CTAP1_ERR_CHANNEL_BUSY;
						return HID_ERROR;
					} else {
						printf2(TAG_ERR, "ignoring random cont packet from %08" PRIx32 nl, pkt->cid);
						return HID_IGNORE;
					}
				}
			}
			if (!is_cont_pkt(pkt)) {

				if (ctaphid_packet_len(pkt) > CTAPHID_BUFFER_SIZE) {
					*cmd = CTAP1_ERR_INVALID_LENGTH;
					return HID_ERROR;
				}
			} else {
				if (buffer_status() == EMPTY || pkt->cid != buffer_cid()) {
					printf2(TAG_ERR, "ignoring random cont packet from %08" PRIx32 nl, pkt->cid);
					return HID_IGNORE;
				}
			}

			if (buffer_packet(pkt) == SEQUENCE_ERROR) {
				printf2(TAG_ERR, "Buffering sequence error" nl);
				*cmd = CTAP1_ERR_INVALID_SEQ;
				return HID_ERROR;
			}
			// TODO: weird race conditions in buffer_packet above (memcpy seems to fix it?)
			// HAL_Delay(200);
			// debug_log("buffer_packet done" nl);
			ret = cid_refresh(pkt->cid);
			if (ret != 0) {
				printf2(TAG_ERR, "Error, refresh cid failed" nl);
				exit(1);
			}
		} else if (is_cont_pkt(pkt)) {
			printf2(TAG_ERR, "ignoring unwarranted cont packet" nl);

			// Ignore
			return HID_IGNORE;
		} else {
			printf2(TAG_ERR, "BUSY" nl);
			*cmd = CTAP1_ERR_CHANNEL_BUSY;
			return HID_ERROR;
		}
	}

	*len = buffer_len();
	*cmd = buffer_cmd();
	return buffer_status();
}

extern void _check_ret(CborError ret, int line, const char *filename);

#define check_hardcore(r)   _check_ret(r,__LINE__, __FILE__);\
                            if ((r) != CborNoError) exit(1);


uint8_t ctaphid_handle_packet(uint8_t *pkt_raw) {

	debug_log(nl nl "ctaphid_handle_packet" nl);

	uint8_t cmd = 0;
	uint32_t cid;
	int len = 0;
	int status;

	static uint8_t is_busy = 0;
	static CTAPHID_WRITE_BUFFER wb;
	CTAP_RESPONSE ctap_resp;

	int bufstatus = ctaphid_buffer_packet(pkt_raw, &cmd, &cid, &len);
	ctaphid_write_buffer_init(&wb);

	wb.cid = cid;
	wb.cmd = cmd;

	if (bufstatus == HID_IGNORE) {
		debug_log("bufstatus == HID_IGNORE" nl);
		return 0;
	}

	if (bufstatus == HID_ERROR) {
		debug_log("bufstatus == HID_ERROR" nl);
		cid_del(cid);
		if (cmd == CTAP1_ERR_INVALID_SEQ) {
			buffer_reset();
		}
		ctaphid_send_error(cid, cmd);
		return 0;
	}

	if (bufstatus == BUFFERING) {
		debug_log("bufstatus == BUFFERING" nl);
		active_cid_timestamp = millis();
		return 0;
	}

	// assert(bufstatus == BUFFERED);

	switch (cmd) {

		case CTAPHID_INIT:
			printf2(TAG_ERR, "CTAPHID_INIT, error this should already be handled" nl);
			exit(1);
			break;

		case CTAPHID_PING:
			info_log(cyan("CTAPHID_PING") nl);

			wb.bcnt = len;
			timestamp();
			ctaphid_write(&wb, ctap_buffer, len);
			ctaphid_write(&wb, NULL, 0);
			printf1(TAG_TIME, "PING writeback: %" PRId32 " ms" nl, timestamp());

			break;

		case CTAPHID_WINK:
			info_log(cyan("CTAPHID_WINK") nl);

			device_wink();

			ctaphid_write(&wb, NULL, 0);

			break;

		case CTAPHID_CBOR:
			info_log(cyan("CTAPHID_CBOR") nl);

			if (len == 0) {
				printf2(TAG_ERR, "Error,invalid 0 length field for cbor packet" nl);
				ctaphid_send_error(cid, CTAP1_ERR_INVALID_LENGTH);
				return 0;
			}

			if (is_busy) {
				printf1(TAG_HID, "Channel busy for CBOR" nl);
				ctaphid_send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
				return 0;
			}

			is_busy = 1;
			ctap_response_init(&ctap_resp);
			status = ctap_request(ctap_buffer, len, &ctap_resp);

			wb.bcnt = (ctap_resp.length + 1);
			wb.cid = cid;
			wb.cmd = cmd;

			timestamp();
			ctaphid_write(&wb, &status, 1);
			ctaphid_write(&wb, ctap_resp.data, ctap_resp.length);
			ctaphid_write(&wb, NULL, 0);
			printf1(TAG_TIME, "CBOR writeback: %" PRId32 " ms" nl, timestamp());
			is_busy = 0;

			break;

		// case CTAPHID_MSG:
		// 	printf1(TAG_HID, "CTAPHID_MSG" nl);
		//
		// 	if (len == 0) {
		// 		printf2(TAG_ERR, "Error, invalid 0 length field for MSG/U2F packet" nl);
		// 		ctaphid_send_error(cid, CTAP1_ERR_INVALID_LENGTH);
		// 		return 0;
		// 	}
		//
		// 	if (is_busy) {
		// 		printf1(TAG_HID, "Channel busy for MSG" nl);
		// 		ctaphid_send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
		// 		return 0;
		// 	}
		//
		// 	is_busy = 1;
		// 	ctap_response_init(&ctap_resp);
		// 	u2f_request((struct u2f_request_apdu *) ctap_buffer, &ctap_resp);
		//
		// 	wb.bcnt = (ctap_resp.length);
		// 	wb.cid = cid;
		// 	wb.cmd = cmd;
		//
		// 	ctaphid_write(&wb, ctap_resp.data, ctap_resp.length);
		// 	ctaphid_write(&wb, NULL, 0);
		// 	is_busy = 0;
		//
		// 	break;

		case CTAPHID_CANCEL:
			info_log(cyan("CTAPHID_CANCEL") nl);
			is_busy = 0;
			break;

		default:
			info_log(red("error, unimplemented HID cmd: %02x"), buffer_cmd());
			ctaphid_send_error(cid, CTAP1_ERR_INVALID_COMMAND);

	}

	cid_del(cid);
	buffer_reset();

	if (!is_busy) {
		return cmd;
	} else {
		return 0;
	}

}
