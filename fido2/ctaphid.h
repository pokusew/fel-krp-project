#ifndef FIDO2_CTAPHID_H
#define FIDO2_CTAPHID_H

#include <stdint.h>
#include <assert.h>

#include "time.h"
#include "linked_list.h"
#include "ctap_errors.h"

#define HID_MESSAGE_SIZE 64

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
#define TYPE_INIT 0x80
#define TYPE_CONT 0x00

// 1.2.9.1. Mandatory commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-mandatory-commands
#define CTAPHID_PING         (TYPE_INIT | 0x01)
#define CTAPHID_MSG          (TYPE_INIT | 0x03)
#define CTAPHID_INIT         (TYPE_INIT | 0x06)
#define CTAPHID_CBOR         (TYPE_INIT | 0x10)
#define CTAPHID_CANCEL       (TYPE_INIT | 0x11)
#define CTAPHID_ERROR        (TYPE_INIT | 0x3F)
#define CTAPHID_KEEPALIVE    (TYPE_INIT | 0x3B)
// 11.2.9.2. Optional commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-optional-commands
#define CTAPHID_LOCK         (TYPE_INIT | 0x04)
#define CTAPHID_WINK         (TYPE_INIT | 0x08)
// 11.2.9.3. Vendor specific commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-vendor-specific-commands
#define CTAPHID_VENDOR_FIRST 0x40
#define CTAPHID_VENDOR_LAST  0x7F

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
#define CTAPHID_PROTOCOL_VERSION    2

#define CTAPHID_STATUS_IDLE         0
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

#define CTAPHID_INIT_PAYLOAD_SIZE  (HID_MESSAGE_SIZE - 7)
#define CTAPHID_CONT_PAYLOAD_SIZE  (HID_MESSAGE_SIZE - 5)

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-channels
#define CTAPHID_BROADCAST_CID 0xffffffff

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
// With a packet size of 64 bytes (max for full-speed devices),
// this means that the maximum message payload length is (64 - 7) + (128 * (64 - 5)) = 7609 bytes.
// one initialization packet + 128 continuation packets
// TODO(pokusew): rename to CTAPHID_MAX_PAYLOAD_LENGTH
#define CTAPHID_BUFFER_SIZE ((HID_MESSAGE_SIZE - 7) + (128 * (HID_MESSAGE_SIZE - 5)))

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
#define CAPABILITY_WINK 0x01
#define CAPABILITY_LOCK 0x02
#define CAPABILITY_CBOR 0x04
#define CAPABILITY_NMSG 0x08

#define CTAP_CAPABILITIES (CAPABILITY_WINK | CAPABILITY_CBOR)

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
typedef struct ctaphid_packet {
	uint32_t cid; // Channel identifier
	union {
		struct {
			uint8_t cmd; // Command identifier (bit 7 always set)
			uint8_t bcnth; // High part of payload length
			uint8_t bcntl; // Low part of payload length
			uint8_t payload[CTAPHID_INIT_PAYLOAD_SIZE];
		} init;
		struct {
			uint8_t seq; // Packet sequence 0x00..0x7f (bit 7 always cleared)
			uint8_t payload[CTAPHID_CONT_PAYLOAD_SIZE];
		} cont;
	} pkt;
} __attribute__((packed)) ctaphid_packet_t;

static_assert(sizeof(ctaphid_packet_t) == HID_MESSAGE_SIZE, "unexpected sizeof(ctaphid_packet_t)");

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
typedef struct ctaphid_init_response_payload {
	uint8_t nonce[8];
	uint32_t cid;
	uint8_t protocol_version;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t version_build;
	uint8_t capabilities;
} __attribute__((packed)) ctaphid_init_response_payload_t;

static_assert(sizeof(ctaphid_init_response_payload_t) == 17, "unexpected sizeof(ctaphid_init_response_payload_t)");

typedef enum ctap_buffer_state {
	EMPTY = 0,
	BUFFERING,
	BUFFERED,
	HID_ERROR,
	HID_IGNORE,
} ctap_buffer_state_t;

typedef struct ctaphid_write_buffer {
	uint32_t cid;
	uint8_t cmd;
	uint16_t bcnt;
	int offset;
	int bytes_written;
	uint8_t seq;
	uint8_t buf[HID_MESSAGE_SIZE];
} ctaphid_write_buffer_t;

typedef struct ctaphid_channel {
	struct ctaphid_channel *prev;
	struct ctaphid_channel *next;
	uint32_t cid;
	millis_t last_used;
	bool busy;
} ctaphid_channel_t;

#define CTAPHID_NUM_CHANNELS 10

// Used to assemble the incoming (request) message on one specific channel.
// Message consists of one initialization pocket and up to 128 continuation packets.
// see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
typedef struct ctaphid_channel_buffer {
	uint32_t cid;
	uint8_t cmd;
	uint16_t bcnt;
	int seq;
	uint8_t payload[CTAPHID_BUFFER_SIZE];
	int offset;
} ctaphid_channel_buffer_t;

typedef void (*ctaphid_cbor_handler_t)(
	void *context,
	uint16_t request_data_length,
	uint8_t *request_data,
	uint8_t *response_status_code,
	uint16_t *response_data_length,
	uint8_t **response_data
);

typedef struct ctaphid_state {

	// Channel IDs (CIDs) are generated in ascending order starting with 1, 2, 3, ... (0xFFFFFFFF - 1).
	// CID 0 is reserved.
	// CID 0xFFFFFFFF is reserved for broadcast commands.
	// see https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-channels
	uint32_t last_cid;
	ctaphid_channel_t channels[CTAPHID_NUM_CHANNELS];
	linked_list_t free_channels;
	linked_list_t used_channels;

	ctaphid_channel_buffer_t buffer;

	ctaphid_write_buffer_t wb;

	ctaphid_cbor_handler_t ctap_handler;
	void *ctap_handler_context;

} ctaphid_state_t;

void ctaphid_init(ctaphid_state_t *state, ctaphid_cbor_handler_t ctap_handler, void *ctap_handler_context);

uint8_t ctaphid_handle_packet(ctaphid_state_t *state, ctaphid_packet_t *pkt);

void ctaphid_check_timeouts(ctaphid_state_t *state);

void ctaphid_update_status(ctaphid_state_t *state, uint8_t status);

#define ctaphid_payload_length(pkt) ((uint16_t)((pkt)->pkt.init.bcnth << 8) | ((pkt)->pkt.init.bcntl))

#endif // FIDO2_CTAPHID_H
