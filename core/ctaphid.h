#ifndef LIONKEY_CTAPHID_H
#define LIONKEY_CTAPHID_H

#include <stdint.h>
#include <assert.h>
#include "compiler.h"

// 11.2.2. Protocol structure and data framing
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-protocol-and-framing
//   Transaction
//      1. Request message (one or more packets) (sent from a host to a device)
//      2. Response message (one or more packets) (sent from a device back to the host)
//      * Once a request has been initiated, the transaction has to be entirely completed
//      or aborted before a second transaction can take place.
//      * A response is never sent without a previous request.
//   Message
//     Request and response messages are in turn divided into individual fragments,
//     known as packets. The packet is the smallest form of protocol data unit,
//     which in the case of CTAPHID are mapped into HID reports.
//   Packet == HID report

// This must be equal to the HID report size.
#ifndef CTAPHID_PACKET_SIZE
#define CTAPHID_PACKET_SIZE 64
#endif

// 11.2.4. Message and packet structure
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
#define CTAPHID_PACKET_TYPE_INIT 0x80
#define CTAPHID_PACKET_TYPE_CONT 0x00

// 11.2.9. CTAPHID commands
// 11.2.9.1. Mandatory commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-mandatory-commands
#define CTAPHID_PING         (CTAPHID_PACKET_TYPE_INIT | 0x01)
#define CTAPHID_MSG          (CTAPHID_PACKET_TYPE_INIT | 0x03)
#define CTAPHID_INIT         (CTAPHID_PACKET_TYPE_INIT | 0x06)
#define CTAPHID_CBOR         (CTAPHID_PACKET_TYPE_INIT | 0x10)
#define CTAPHID_CANCEL       (CTAPHID_PACKET_TYPE_INIT | 0x11)
#define CTAPHID_ERROR        (CTAPHID_PACKET_TYPE_INIT | 0x3F)
#define CTAPHID_KEEPALIVE    (CTAPHID_PACKET_TYPE_INIT | 0x3B)
// 11.2.9.2. Optional commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-optional-commands
#define CTAPHID_LOCK         (CTAPHID_PACKET_TYPE_INIT | 0x04)
#define CTAPHID_WINK         (CTAPHID_PACKET_TYPE_INIT | 0x08)
// 11.2.9.3. Vendor specific commands
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-vendor-specific-commands
#define CTAPHID_VENDOR_FIRST 0x40
#define CTAPHID_VENDOR_LAST  0x7F

// defined in 11.2.9.1.3. CTAPHID_INIT (0x06):
//   Response at success:
//     DATA+12: CTAPHID protocol version identifier
//     >> The protocol version identifies the protocol version implemented by the device.
//        This version of the CTAPHID protocol is 2.
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
#define CTAPHID_PROTOCOL_VERSION    2

#define CTAPHID_PACKET_INIT_PAYLOAD_SIZE  (CTAPHID_PACKET_SIZE - 7)
#define CTAPHID_PACKET_CONT_PAYLOAD_SIZE  (CTAPHID_PACKET_SIZE - 5)

// 1.2.3. Concurrency and channels
// >> Channel ID 0 is reserved and 0xffffffff is reserved for broadcast commands,
//    i.e. at the time of channel allocation.
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-channels
#define CTAPHID_BROADCAST_CID 0xffffffff

// 11.2.4. Message and packet structure
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
// >> With a packet size of 64 bytes (max for full-speed devices),
//    this means that the maximum message payload length is (64 - 7) + (128 * (64 - 5)) = 7609 bytes.
// one initialization packet + 128 continuation packets (packet sequence number is the 7-bit SEQ = 0..127 -> 128)
#define CTAPHID_MAX_PAYLOAD_LENGTH (CTAPHID_PACKET_INIT_PAYLOAD_SIZE + (128 * CTAPHID_PACKET_CONT_PAYLOAD_SIZE))
// a static assert with one test case to make sure our CTAPHID size-related macros work correctly
static_assert(
	CTAPHID_PACKET_SIZE != 64 || CTAPHID_MAX_PAYLOAD_LENGTH == 7609,
	"The following implication must hold: (CTAPHID_PACKET_SIZE == 64) => (CTAPHID_MAX_PAYLOAD_LENGTH == 7609)"
);

// defined in 11.2.9.1.3. CTAPHID_INIT (0x06)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
#define CTAPHID_CAPABILITY_WINK 0x01
#define CTAPHID_CAPABILITY_LOCK 0x02
#define CTAPHID_CAPABILITY_CBOR 0x04
#define CTAPHID_CAPABILITY_NMSG 0x08

// 11.2.4. Message and packet structure
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-message-and-packet-structure
typedef struct LION_ATTR_PACKED ctaphid_packet {
	uint32_t cid; // Channel identifier
	union {
		struct ctaphid_packet_init {
			uint8_t cmd; // Command identifier (bit 7 always set)
			uint8_t bcnth; // High part of payload length
			uint8_t bcntl; // Low part of payload length
			uint8_t payload[CTAPHID_PACKET_INIT_PAYLOAD_SIZE];
		} init;
		struct ctaphid_packet_cont {
			uint8_t seq; // Packet sequence 0x00..0x7f (bit 7 always cleared)
			uint8_t payload[CTAPHID_PACKET_CONT_PAYLOAD_SIZE];
		} cont;
	} pkt;
} ctaphid_packet_t;
static_assert(
	sizeof(ctaphid_packet_t) == CTAPHID_PACKET_SIZE,
	"unexpected sizeof(ctaphid_packet_t)"
);
static_assert(
	sizeof(struct ctaphid_packet_init) == CTAPHID_PACKET_SIZE - sizeof(uint32_t),
	"unexpected sizeof(struct ctaphid_packet_init)"
);
static_assert(
	sizeof(struct ctaphid_packet_cont) == CTAPHID_PACKET_SIZE - sizeof(uint32_t),
	"unexpected sizeof(struct ctaphid_packet_cont)"
);

// 11.2.9.1.3. CTAPHID_INIT (0x06)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-init
// Response at success
typedef struct LION_ATTR_PACKED ctaphid_init_response_payload {
	uint8_t nonce[8];
	uint32_t cid;
	uint8_t protocol_version;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t version_build;
	uint8_t capabilities;
} ctaphid_init_response_payload_t;

static_assert(sizeof(ctaphid_init_response_payload_t) == 17, "unexpected sizeof(ctaphid_init_response_payload_t)");

#endif // LIONKEY_CTAPHID_H
