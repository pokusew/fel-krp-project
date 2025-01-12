#ifndef POKUSEW_CTAP_PARSE_H
#define POKUSEW_CTAP_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "ctap_errors.h"

#define nl "\n"

#define cbor_decoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP2_ERR_INVALID_CBOR;                   \
    }                                                    \
    ((void) 0)


#if LIONKEY_LOG & 0x1

#define lionkey_cbor_error_log(err, line, filename) \
	printf("CborError: 0x%x (%d) (%s) at %s:%d" nl, err, err, cbor_error_string(err), filename, line)

#else
#define lionkey_cbor_error_log(err, line, filename) ((void) 0)
#endif


// https://cbor.io/
// CBOR Object Signing and Encryption (COSE)
// RFC 8152
// https://datatracker.ietf.org/doc/html/rfc8152
// https://datatracker.ietf.org/doc/html/rfc8152#section-7
typedef struct COSE_Key {
	struct {
		uint8_t x[32];
		uint8_t y[32];
	} pubkey;

	int kty;
	int crv;
} COSE_Key;

// request (message)
// CTAPHID_CBOR
//    	CTAP command byte
//      n bytes of CBOR encoded data

// response (message)
// CTAPHID_CBOR
//    	CTAP status code
//      n bytes of CBOR encoded data

#define NEW_PIN_ENC_MAX_SIZE        256     // includes NULL terminator
#define NEW_PIN_ENC_MIN_SIZE        64
#define NEW_PIN_MAX_SIZE            64
#define NEW_PIN_MIN_SIZE            4

// Command
// code (one byte)
// command parameters are encoded using a CBOR map (CBOR major type 5)
// The CBOR map MUST be encoded using the definite length variant.

// 6.5. authenticatorClientPIN (0x06) command

// 6.5.5. authenticatorClientPIN (0x06) Command Definition
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
typedef struct CTAP_clientPIN {
	int pinUvAuthProtocol;
	int subCommand;
	COSE_Key keyAgreement;
	bool keyAgreementPresent;
	uint8_t pinUvAuthParam[16];
	bool pinUvAuthParamPresent;
	uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
	int newPinEncSize;
	uint8_t pinHashEnc[16];
	bool pinHashEncPresent;
	int permissions;
	bool permissionsPresent;
	int rpId;
	bool rpIdPresent;
} CTAP_clientPIN;

// 6.5.5. authenticatorClientPIN (0x06) Command Definition
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
// The command takes the following input parameters:
#define CTAP_clientPIN_pinUvAuthProtocol  0x01
#define CTAP_clientPIN_subCommand         0x02
#define CTAP_clientPIN_keyAgreement       0x03
#define CTAP_clientPIN_pinUvAuthParam     0x04
#define CTAP_clientPIN_newPinEnc          0x05
#define CTAP_clientPIN_pinHashEnc         0x06
#define CTAP_clientPIN_permissions        0x09
#define CTAP_clientPIN_rpId               0x0A
// The authenticatorClientPIN subCommands are:
#define CTAP_clientPIN_subCmd_getPINRetries                             0x01
#define CTAP_clientPIN_subCmd_getKeyAgreement                           0x02
#define CTAP_clientPIN_subCmd_setPIN                                    0x03
#define CTAP_clientPIN_subCmd_changePIN                                 0x04
#define CTAP_clientPIN_subCmd_getPinToken                               0x05
#define CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingUvWithPermissions   0x06
// (unused)                                                             0x08
#define CTAP_clientPIN_subCmd_getUVRetries                              0x07
#define CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingPinWithPermissions  0x09


uint8_t ctap_parse_client_pin(const uint8_t *request, size_t length, CTAP_clientPIN *cp);

#endif // POKUSEW_CTAP_PARSE_H
