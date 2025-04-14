#ifndef LIONKEY_CTAP_PARSE_H
#define LIONKEY_CTAP_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <cbor.h>

#include "ctap_errors.h"
#include "cose.h"
#include "compiler.h"

#define ctap_parse_check(expr)                                                   \
	if ((ret = (expr)) != CTAP2_OK) {                                            \
		debug_log(                                                               \
			red("ctap_parse_check: 0x%02" wPRIx8 " (%" wPRIu8 ") at %s:%d") nl,  \
			ret, ret, __FILE__, __LINE__                                         \
		);                                                                       \
		return ret;                                                              \
	}                                                                            \
	((void) 0)

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
	debug_log(red("CborError: 0x%x (%d) (%s) at %s:%d") nl, err, err, cbor_error_string(err), filename, line)

#else
#define lionkey_cbor_error_log(err, line, filename) ((void) 0)
#endif

#define lion_array(name, max_size) \
	size_t name##_size; \
	uint8_t name[max_size]

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
#define CTAP_NEW_PIN_ENC_MAX_SIZE        80 // = max(64, 80)
#define CTAP_NEW_PIN_ENC_MIN_SIZE        64 // = min(64, 80)
// pinUvAuthParam pinUvAuthProtocol 1 = 16 bytes
// pinUvAuthParam pinUvAuthProtocol 2 = 32 bytes
#define CTAP_PIN_UV_AUTH_PARAM_MAX_SIZE  32 // = max(16, 32)
#define CTAP_PIN_UV_AUTH_PARAM_MIN_SIZE  16 // = min(16, 32)
// pinHashEnc pinUvAuthProtocol 1 = 16 bytes
// pinHashEnc pinUvAuthProtocol 2 = 32 bytes (16 + 16)
#define CTAP_PIN_HASH_ENC_MAX_SIZE       32 // = max(16, 32)
#define CTAP_PIN_HASH_ENC_MIN_SIZE       16 // = min(16, 32)

// Command
// code (one byte)
// command parameters are encoded using a CBOR map (CBOR major type 5)
// The CBOR map MUST be encoded using the definite length variant.

#define CTAP_RP_ID_MAX_SIZE 255

#define CTAP_USER_ENTITY_ID_MAX_SIZE 64

// see https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-displayname
//   When storing a displayName member's value,
//   the value MAY be truncated as described in 6.4.1 String Truncation
//   (https://w3c.github.io/webauthn/#sctn-strings-truncation)
//   using a size limit greater than or equal to 64 bytes.
#define CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE 64

static_assert(
	sizeof(char) == sizeof(uint8_t),
	"sizeof(char) == sizeof(uint8_t)"
);

#define ctap_param_to_mask(number) (1u << ((number) * lion_static_assert_expr(0 <= (number) && (number) < 31, \
	"number must be in range [0, 31] as it is used as a bitshift")))

static_assert(
	ctap_param_to_mask(5) == (1u << 5),
	"ctap_param_to_mask() macro does not work correctly"
);

LION_ATTR_ALWAYS_INLINE static inline bool ctap_is_present(uint32_t present, uint32_t mask) {
	return (present & mask) == mask;
}

LION_ATTR_ALWAYS_INLINE static inline bool ctap_is_present_some(uint32_t present, uint32_t mask) {
	return (present & mask) != 0u;
}

#define ctap_set_present(params_ptr, param_number) \
    (params_ptr)->present |= ctap_param_to_mask(param_number)

#define ctap_param_is_present(params_ptr, param_number) \
    ctap_is_present((params_ptr)->present, ctap_param_to_mask(param_number))

// https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity
typedef struct CTAP_userEntity {
	// "an empty account identifier is valid" => id_size might be 0
	size_t id_size;
	// The user handle of the user account.
	// A user handle is an opaque byte sequence with a maximum size of 64 bytes,
	// and is not meant to be displayed to the user.
	uint8_t id[CTAP_USER_ENTITY_ID_MAX_SIZE];
	// The following is possible: displayName_present == true && displayName_size == 0
	bool displayName_present;
	size_t displayName_size;
	uint8_t displayName[CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE];
} CTAP_userEntity;

// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
typedef struct CTAP_rpId {
	size_t id_size;
	uint8_t id[CTAP_RP_ID_MAX_SIZE];
} CTAP_rpId;

bool ctap_rp_id_matches(const CTAP_rpId *rp_id_a, const CTAP_rpId *rp_id_b);

// WebAuthn 5.8.5. Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)
// https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
typedef int32_t COSEAlgorithmIdentifier;

// https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
#define CTAP_pubKeyCredType_public_key   (1u << 0)

// WebAuthn 5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
typedef struct CTAP_credParams {
	uint8_t type;
	COSEAlgorithmIdentifier alg;
} CTAP_credParams;

// 12. Defined Extensions
#define CTAP_extension_credProtect   (1u << 0)
#define CTAP_extension_hmac_secret   (1u << 1)
#define CTAP_extension_minPinLength  (1u << 2)
// 12.1. Credential Protection (credProtect)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension
#define CTAP_extension_credProtect_userVerificationOptional                      0x01
#define CTAP_extension_credProtect_userVerificationOptionalWithCredentialIDList  0x02
#define CTAP_extension_credProtect_userVerificationRequired                      0x03

// 6.1. authenticatorMakeCredential (0x01)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
// This method is invoked by the host to request generation of a new credential in the authenticator.
// It takes the following input parameters, several of which correspond
// to those defined in the authenticatorMakeCredential operation section
// of the Web Authentication specification:
#define CTAP_makeCredential_clientDataHash         0x01
#define CTAP_makeCredential_rp                     0x02
#define CTAP_makeCredential_user                   0x03
#define CTAP_makeCredential_pubKeyCredParams       0x04
#define CTAP_makeCredential_excludeList            0x05
#define CTAP_makeCredential_extensions             0x06
#define CTAP_makeCredential_options                0x07
#define CTAP_makeCredential_pinUvAuthParam         0x08
#define CTAP_makeCredential_pinUvAuthProtocol      0x09
#define CTAP_makeCredential_enterpriseAttestation  0x0A
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#makecred-option-key
#define CTAP_makeCredential_option_rk          (1u << 0)
#define CTAP_makeCredential_option_up          (1u << 1)
#define CTAP_makeCredential_option_uv          (1u << 2)
typedef struct CTAP_makeCredential {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	uint8_t clientDataHash[32]; // SHA-256 digest (32 bytes)
	CTAP_rpId rpId;
	CTAP_userEntity user;
	CborValue pubKeyCredParams;
	CTAP_credParams pubKeyCredParams_chosen;
	CborValue excludeList;
	uint8_t extensions_present;
	uint8_t credProtect;
	uint8_t options_present;
	uint8_t options_values;
	lion_array(pinUvAuthParam, CTAP_PIN_UV_AUTH_PARAM_MAX_SIZE);
	uint8_t pinUvAuthProtocol;
} CTAP_makeCredential;
// On success, the authenticator returns the following authenticatorMakeCredential response structure
// which contains an attestation object plus additional information.
#define CTAP_makeCredential_res_fmt           0x01
#define CTAP_makeCredential_res_authData      0x02
#define CTAP_makeCredential_res_attStmt       0x03
#define CTAP_makeCredential_res_epAtt         0x04
#define CTAP_makeCredential_res_largeBlobKey  0x05

// 6.5. authenticatorClientPIN (0x06) command
// 6.5.5. authenticatorClientPIN (0x06) Command Definition
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
typedef struct CTAP_clientPIN {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	uint8_t pinUvAuthProtocol; // optional
	uint8_t subCommand; // REQUIRED
	COSE_Key keyAgreement; // optional
	lion_array(pinUvAuthParam, CTAP_PIN_UV_AUTH_PARAM_MAX_SIZE); // optional
	lion_array(newPinEnc, CTAP_NEW_PIN_ENC_MAX_SIZE); // optional
	lion_array(pinHashEnc, CTAP_PIN_HASH_ENC_MAX_SIZE); // optional
	uint32_t permissions; // optional
	CTAP_rpId rpId; // optional
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

// 6.4. authenticatorGetInfo (0x04)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo
// On success, the authenticator returns the following authenticatorGetInfo response structure:
#define CTAP_authenticatorGetInfo_res_versions                          0x01
#define CTAP_authenticatorGetInfo_res_extensions                        0x02
#define CTAP_authenticatorGetInfo_res_aaguid                            0x03
#define CTAP_authenticatorGetInfo_res_options                           0x04
#define CTAP_authenticatorGetInfo_res_maxMsgSize                        0x05
#define CTAP_authenticatorGetInfo_res_pinUvAuthProtocols                0x06
#define CTAP_authenticatorGetInfo_res_maxCredentialCountInList          0x07
#define CTAP_authenticatorGetInfo_res_maxCredentialIdLength             0x08
#define CTAP_authenticatorGetInfo_res_transports                        0x09
#define CTAP_authenticatorGetInfo_res_algorithms                        0x0A
#define CTAP_authenticatorGetInfo_res_maxSerializedLargeBlobArray       0x0B
#define CTAP_authenticatorGetInfo_res_forcePINChange                    0x0C
#define CTAP_authenticatorGetInfo_res_minPINLength                      0x0D
#define CTAP_authenticatorGetInfo_res_firmwareVersion                   0x0E
#define CTAP_authenticatorGetInfo_res_maxCredBlobLength                 0x0F
#define CTAP_authenticatorGetInfo_res_maxRPIDsForSetMinPINLength        0x10
#define CTAP_authenticatorGetInfo_res_preferredPlatformUvAttempts       0x11
#define CTAP_authenticatorGetInfo_res_uvModality                        0x12
#define CTAP_authenticatorGetInfo_res_certifications                    0x13
#define CTAP_authenticatorGetInfo_res_remainingDiscoverableCredentials  0x14
#define CTAP_authenticatorGetInfo_res_vendorPrototypeConfigCommands     0x15

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

LION_ATTR_ALWAYS_INLINE static inline bool ctap_permissions_include_any_of(uint32_t permissions, uint32_t mask) {
	return (permissions & mask) != 0u;
}

LION_ATTR_ALWAYS_INLINE static inline uint8_t ctap_init_cbor_parser(
	const uint8_t *data,
	size_t data_size,
	CborParser *parser,
	CborValue *it
) {
	CborError err;
	cbor_decoding_check(
		cbor_parser_init(
			data,
			data_size,
			0,
			parser,
			it
		)
	);
	return CTAP2_OK;
}

uint8_t ctap_parse_client_pin(CborValue *it, CTAP_clientPIN *params);

uint8_t ctap_parse_make_credential(CborValue *it, CTAP_makeCredential *params);

uint8_t ctap_parse_make_credential_pub_key_cred_params(CTAP_makeCredential *params);

#endif // LIONKEY_CTAP_PARSE_H
