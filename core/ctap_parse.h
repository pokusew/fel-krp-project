#ifndef POKUSEW_CTAP_PARSE_H
#define POKUSEW_CTAP_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "ctap_errors.h"

#define cbor_decoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP2_ERR_INVALID_CBOR;                   \
    }                                                    \
    ((void) 0)

#define cbor_encoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP1_ERR_OTHER;                          \
    }                                                    \
    ((void) 0)

#if LIONKEY_LOG & 0x1

#include "utils.h"

#define lionkey_cbor_error_log(err, line, filename) \
	debug_log("CborError: 0x%x (%d) (%s) at %s:%d" nl, err, err, cbor_error_string(err), filename, line)

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

// Identification of the key type
#define COSE_KEY_LABEL_KTY      1
// Key usage restriction to this algorithm
#define COSE_KEY_LABEL_ALG      3
// CRV = curve, values from Table 22
#define COSE_KEY_LABEL_CRV      -1
#define COSE_KEY_LABEL_X        -2
#define COSE_KEY_LABEL_Y        -3

// https://datatracker.ietf.org/doc/html/rfc8152#section-13
// OKP = Octet Key Pair
#define COSE_KEY_KTY_OKP        1
// Elliptic Curve Keys w/ x- and y-coordinate pair
#define COSE_KEY_KTY_EC2        2

// NIST P-256 also known as secp256r1
#define COSE_KEY_CRV_P256       1
// Ed25519 for use w/ EdDSA only
#define COSE_KEY_CRV_ED25519    6

// ECDSA w/ SHA-256
// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
#define COSE_ALG_ES256            -7
// EdDSA
// https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
#define COSE_ALG_EDDSA            -8
#define COSE_ALG_ECDH_ES_HKDF_256 -25

// request (message)
// CTAPHID_CBOR
//    	CTAP command byte
//      n bytes of CBOR encoded data

// response (message)
// CTAPHID_CBOR
//    	CTAP status code
//      n bytes of CBOR encoded data

// newPinEnc pinUvAuthProtocol 1 = 64 bytes
// newPinEnc pinUvAuthProtocol 2 = 80 bytes (16 + 64)
#define NEW_PIN_ENC_MAX_SIZE        80 // = max(64, 80)
#define NEW_PIN_ENC_MIN_SIZE        64 // = min(64, 80)
// pinUvAuthParam pinUvAuthProtocol 1 = 16 bytes
// pinUvAuthParam pinUvAuthProtocol 2 = 32 bytes
#define PIN_UV_AUTH_PARAM_MAX_SIZE  32 // = max(16, 32)
#define PIN_UV_AUTH_PARAM_MIN_SIZE  16 // = min(16, 32)
// pinHashEnc pinUvAuthProtocol 1 = 16 bytes
// pinHashEnc pinUvAuthProtocol 2 = 32 bytes (16 + 16)
#define PIN_HASH_ENC_MIN_SIZE       16 // = min(16, 32)
#define PIN_HASH_ENC_MAX_SIZE       32 // = min(16, 32)

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
	uint8_t pinUvAuthParam[PIN_UV_AUTH_PARAM_MAX_SIZE];
	size_t pinUvAuthParamSize;
	bool pinUvAuthParamPresent;
	uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
	size_t newPinEncSize;
	uint8_t pinHashEnc[PIN_HASH_ENC_MAX_SIZE];
	size_t pinHashEncSize;
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
#define CTAP_clientPIN_subCmd_getUVRetries                              0x07
#define CTAP_clientPIN_subCmd_0x08                                      0x08
#define CTAP_clientPIN_subCmd_getPinUvAuthTokenUsingPinWithPermissions  0x09
// On success, authenticator returns the following structure in its response:
#define CTAP_clientPIN_res_keyAgreement     0x01
#define CTAP_clientPIN_res_pinUvAuthToken   0x02
#define CTAP_clientPIN_res_pinRetries       0x03
#define CTAP_clientPIN_res_powerCycleState  0x04
#define CTAP_clientPIN_res_uvRetries        0x05

// 6.5.5.7. Operations to Obtain a pinUvAuthToken
// The following pinUvAuthToken permissions are defined:

/**
 * MakeCredential
 * RP ID: Required
 * This allows the pinUvAuthToken to be used for authenticatorMakeCredential operations
 * with the provided rpId parameter.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_mc    0x01

/**
 * GetAssertion
 * RP ID: Required
 * This allows the pinUvAuthToken to be used for authenticatorGetAssertion operations
 * with the provided rpId parameter.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_ga    0x02

/**
 * Credential Management
 * RP ID: Optional
 * This allows the pinUvAuthToken to be used with the authenticatorCredentialManagement command.
 * The rpId parameter is optional, if it is present, the pinUvAuthToken can only be used
 * for Credential Management operations on Credentials associated with that RP ID.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_cm    0x04

/**
 * Bio Enrollment
 * RP ID: Ignored
 * This allows the pinUvAuthToken to be used with the authenticatorBioEnrollment command.
 * The rpId parameter is ignored for this permission.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_be    0x08

/**
 * Large Blob Write
 * RP ID: Ignored
 * This allows the pinUvAuthToken to be used with the authenticatorLargeBlobs command.
 * The rpId parameter is ignored for this permission.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_lbw   0x10

/**
 * Authenticator Configuration
 * RP ID: Ignored
 * This allows the pinUvAuthToken to be used with the authenticatorConfig command.
 * The rpId parameter is ignored for this permission.
 */
#define CTAP_clientPIN_pinUvAuthToken_permission_acfg  0x20

static inline bool permissions_include_any_of(int permissions, int mask) {
	return (permissions & mask) != 0;
}

uint8_t ctap_parse_client_pin(const uint8_t *request, size_t length, CTAP_clientPIN *cp);

#endif // POKUSEW_CTAP_PARSE_H
