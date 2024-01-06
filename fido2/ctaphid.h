#ifndef FIDO2_CTAPHID_H
#define FIDO2_CTAPHID_H

#include "device.h"
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
typedef struct {
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
} CTAPHID_PACKET;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
typedef struct {
	uint8_t nonce[8];
	uint32_t cid;
	uint8_t protocol_version;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t version_build;
	uint8_t capabilities;
} __attribute__((packed)) CTAPHID_INIT_RESPONSE;

void ctaphid_init();

uint8_t ctaphid_handle_packet(uint8_t *pkt_raw);

void ctaphid_check_timeouts();

void ctaphid_update_status(int8_t status);

#define ctaphid_packet_len(pkt) ((uint16_t)((pkt)->pkt.init.bcnth << 8) | ((pkt)->pkt.init.bcntl))

#endif // FIDO2_CTAPHID_H
