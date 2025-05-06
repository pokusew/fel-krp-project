#ifndef LIONKEY_CTAP_PARSE_H
#define LIONKEY_CTAP_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <cbor.h>

#include "ctap_errors.h"
#include "cose.h"
#include "compiler.h"
#include "utils.h"

#define ctap_check(expr)                                                   \
	if ((ret = (expr)) != CTAP2_OK) {                                      \
		debug_log(                                                         \
			red("ctap_check: 0x%02" wPRIx8 " (%" wPRIu8 ") at %s:%d") nl,  \
			ret, ret, __FILE__, __LINE__                                   \
		);                                                                 \
		return ret;                                                        \
	}                                                                      \
	((void) 0)

#define lionkey_cbor_error_log(err, line, filename) \
	debug_log(red("CborError: 0x%x (%d) (%s) at %s:%d") nl, err, err, cbor_error_string(err), filename, line)

#define ctap_cbor_ensure_type(result)                          \
	if (!(result)) {                                           \
		debug_log(                                             \
			red("CTAP2_ERR_CBOR_UNEXPECTED_TYPE at %s:%d") nl, \
			__FILE__, __LINE__                                 \
		);                                                     \
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;                 \
	}                                                          \
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

typedef struct ctap_string {
	size_t size;
	const uint8_t *data;
} ctap_string_t;

#define ctap_str(str) ((const ctap_string_t) {.size = sizeof((str)) - 1, .data = (const uint8_t *) (str)})

bool ctap_string_matches(const ctap_string_t *a, const ctap_string_t *b);

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

#define CTAP_SHA256_HASH_SIZE  32

// Command
// code (one byte)
// command parameters are encoded using a CBOR map (CBOR major type 5)
// The CBOR map MUST be encoded using the definite length variant.

// We chose this limit in our implementation (LionKey) to simplify operations with RP IDs
// (to reduce memory requirements).
#define CTAP_RP_ID_MAX_SIZE 255
static_assert(
	CTAP_RP_ID_MAX_SIZE >= 32,
	"CTAP 2.1 violation: If authenticators store relying party identifiers at all, they MUST store at least 32 bytes"
	// see 6.8.7. Truncation of relying party identifiers
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#rpid-truncation
);

// This limit is imposed by the WebAuthn spec
// https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
#define CTAP_USER_ENTITY_ID_MAX_SIZE 64

// see https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-displayname
//   When storing a displayName member's value,
//   the value MAY be truncated as described in 6.4.1 String Truncation
//   (https://w3c.github.io/webauthn/#sctn-strings-truncation)
//   using a size limit greater than or equal to 64 bytes.
#define CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE 64

// see https://w3c.github.io/webauthn/#dom-publickeycredentialentity-name
//   When storing a name member's value,
//   the value MAY be truncated as described in 6.4.1 String Truncation
//   (https://w3c.github.io/webauthn/#sctn-strings-truncation)
//   using a size limit greater than or equal to 64 bytes.
#define CTAP_USER_ENTITY_NAME_MAX_SIZE 64

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

// https://w3c.github.io/webauthn/#user-handle
// https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
// The user handle of the user account.
// A user handle is an opaque byte sequence with a maximum size of 64 bytes,
// and is not meant to be displayed to the user.
// "an empty account identifier is valid" => size might be 0
typedef ctap_string_t CTAP_userHandle;

// https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity
typedef struct CTAP_userEntity {
	uint32_t present; // not a field, holds parsing info (if field was parsed, i.e., present)
	CTAP_userHandle id;
	ctap_string_t name;
	ctap_string_t displayName;
} CTAP_userEntity;
#define CTAP_userEntity_id           0x01
#define CTAP_userEntity_name         0x02
#define CTAP_userEntity_displayName  0x03

// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
typedef ctap_string_t CTAP_rpId;

// https://w3c.github.io/webauthn/#credential-id
//   Note that the WebAuthn spec implies that every Credential ID
//   is at least 16 bytes long and at most 1023 bytes long.
// We chose this limit in our implementation (LionKey) since we know that any Credential ID
// generated by us is always at most 128 bytes.
// (to reduce memory requirements).
#define CTAP_CRED_ID_MAX_SIZE 128
typedef ctap_string_t CTAP_credId;

// https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor
typedef struct CTAP_credDesc {
	uint8_t type;
	CTAP_credId id;
} CTAP_credDesc;

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

#define CTAP_AAGUID_SIZE 16

#define CTAP_CREDENTIAL_ID_MAX_SIZE 128

// {
//     "credProtect": 1, // or 2 or 3
//     "hmac-secret": true,
// }
#define CTAP_authenticator_data_extensions_MAX_SIZE 27

// WebAuthn 6.5.1. Attested Credential Data
// https://w3c.github.io/webauthn/#attested-credential-data
#define CTAP_CREDENTIAL_PUBLIC_KEY_COSE_ENCODED_MAX_SIZE 100 // TODO: review and update this max_site
typedef struct LION_ATTR_PACKED CTAP_authenticator_data_attestedCredentialData {
	struct LION_ATTR_PACKED {
		// 	The AAGUID of the authenticator.
		uint8_t aaguid[CTAP_AAGUID_SIZE];
		// Byte length L of credentialId, 16-bit unsigned big-endian integer. Value MUST be <= 1023.
		uint16_t credentialIdLength;
	} fixed_header;
	// credentialId:
	//   Credential ID
	// credentialPublicKey:
	//   The credential public key encoded in COSE_Key format,
	//   as defined in Section 7 of [RFC9052], using the CTAP2 canonical CBOR encoding form.
	uint8_t variable_data[CTAP_CREDENTIAL_ID_MAX_SIZE + CTAP_CREDENTIAL_PUBLIC_KEY_COSE_ENCODED_MAX_SIZE];
} CTAP_authenticator_data_attestedCredentialData;

// WebAuthn 6.1. Authenticator Data
// https://w3c.github.io/webauthn/#authenticator-data
typedef struct LION_ATTR_PACKED CTAP_authenticator_data {
	struct LION_ATTR_PACKED {
		uint8_t rpIdHash[CTAP_SHA256_HASH_SIZE]; // SHA-256 hash of the RP ID the credential is scoped to.
		uint8_t flags; // Flags (bit 0 is the least significant bit):
		uint32_t signCount; // Signature counter, 32-bit unsigned big-endian integer.
	} fixed_header;
	// attestedCredentialData (variable length, may not be present at all)
	//   attested credential data (if present). See 6.5.1 Attested Credential Data for details.
	//   Its length depends on the length of the credential ID and credential public key being attested.
	// extensions (variable length, may not be present at all)
	//   Extension-defined authenticator data. This is a CBOR [RFC8949] map with extension identifiers as keys,
	//   and authenticator extension outputs as values. See 9. WebAuthn Extensions for details.
	uint8_t variable_data[
		sizeof(CTAP_authenticator_data_attestedCredentialData)
		+ CTAP_authenticator_data_extensions_MAX_SIZE
	];
} CTAP_authenticator_data;
static_assert(
	sizeof(CTAP_authenticator_data) ==
	37 // fixed_header
	+ CTAP_authenticator_data_extensions_MAX_SIZE
	+ sizeof(CTAP_authenticator_data_attestedCredentialData),
	"unexpected sizeof(CTAP_authenticator_data)"
);

// Bit 0: User Present (UP) result.
// * 1 means the user is present.
// * 0 means the user is not present.
#define CTAP_authenticator_data_flags_up   (1u << 0)
// Bit 1: Reserved for future use (RFU1).
#define CTAP_authenticator_data_flags_rfu1 (1u << 1)
// Bit 2: User Verified (UV) result.
// * 1 means the user is verified.
// * 0 means the user is not verified.
#define CTAP_authenticator_data_flags_uv   (1u << 2)
// Bit 3: Backup Eligibility (BE).
// * 1 means the public key credential source is backup eligible.
// * 0 means the public key credential source is not backup eligible.
#define CTAP_authenticator_data_flags_be   (1u << 3)
// Bit 4: Backup State (BS).
// * 1 means the public key credential source is currently backed up.
// * 0 means the public key credential source is not currently backed up.
#define CTAP_authenticator_data_flags_bs   (1u << 4)
// Bit 5: Reserved for future use (RFU2).
#define CTAP_authenticator_data_flags_rfu2 (1u << 5)
// Bit 6: Attested credential data included (AT).
// * Indicates whether the authenticator added attested credential data.
#define CTAP_authenticator_data_flags_at   (1u << 6)
// Bit 7: Extension data included (ED).
// * Indicates if the authenticator data has extensions.
#define CTAP_authenticator_data_flags_ed   (1u << 7)

// 6.4. authenticatorGetInfo (0x04) options:
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#option-id
#define CTAP_getInfo_option_plat                             (1u << 0)
#define CTAP_getInfo_option_rk                               (1u << 1)
#define CTAP_getInfo_option_clientPin                        (1u << 2)
#define CTAP_getInfo_option_up                               (1u << 3)
#define CTAP_getInfo_option_uv                               (1u << 4)
#define CTAP_getInfo_option_pinUvAuthToken                   (1u << 5)
#define CTAP_getInfo_option_noMcGaPermissionsWithClientPin   (1u << 6)
#define CTAP_getInfo_option_largeBlobs                       (1u << 7)
#define CTAP_getInfo_option_ep                               (1u << 8)
#define CTAP_getInfo_option_bioEnroll                        (1u << 9)
#define CTAP_getInfo_option_userVerificationMgmtPreview      (1u << 10)
#define CTAP_getInfo_option_uvBioEnroll                      (1u << 11)
#define CTAP_getInfo_option_authnrCfg                        (1u << 12)
#define CTAP_getInfo_option_uvAcfg                           (1u << 13)
#define CTAP_getInfo_option_credMgmt                         (1u << 14)
#define CTAP_getInfo_option_makeCredUvNotRqd                 (1u << 15)
#define CTAP_getInfo_option_alwaysUv                         (1u << 16)

// 12. Defined Extensions
#define CTAP_extension_credProtect   (1u << 0)
#define CTAP_extension_hmac_secret   (1u << 1)
#define CTAP_extension_minPinLength  (1u << 2)
// 12.1. Credential Protection (credProtect)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension
#define CTAP_extension_credProtect_1_userVerificationOptional                      0x01
#define CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList  0x02
#define CTAP_extension_credProtect_3_userVerificationRequired                      0x03
// 12.5. HMAC Secret Extension (hmac-secret)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension
// authenticatorGetAssertion additional behaviors
#define CTAP_getAssertion_hmac_secret_keyAgreement       0x01
#define CTAP_getAssertion_hmac_secret_saltEnc            0x02
#define CTAP_getAssertion_hmac_secret_saltAuth           0x03
#define CTAP_getAssertion_hmac_secret_pinUvAuthProtocol  0x04
typedef struct CTAP_getAssertion_hmac_secret {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	COSE_Key keyAgreement;
	ctap_string_t saltEnc;
	ctap_string_t saltAuth;
	uint8_t pinUvAuthProtocol;
} CTAP_getAssertion_hmac_secret;

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
// options for makeCredential: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#makecred-option-key
// options for getAssertion: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getassert-option-key
#define CTAP_ma_ga_option_rk  (1u << 0)
#define CTAP_ma_ga_option_up  (1u << 1)
#define CTAP_ma_ga_option_uv  (1u << 2)
typedef struct CTAP_mc_ga_options {
	uint8_t present;
	uint8_t values;
} CTAP_mc_ga_options;
typedef struct CTAP_mc_ga_common {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	ctap_string_t clientDataHash; // SHA-256 digest (32 bytes)
	CTAP_rpId rpId;
	uint8_t extensions_present;
	CTAP_mc_ga_options options;
	ctap_string_t pinUvAuthParam;
	uint8_t pinUvAuthProtocol;
	uint8_t rpId_hash[CTAP_SHA256_HASH_SIZE]; // (not a param, computed in ctap_make_credential()/ctap_get_assertion())
} CTAP_mc_ga_common;
typedef struct CTAP_makeCredential {
	CTAP_mc_ga_common common;
	CTAP_userEntity user;
	CborValue pubKeyCredParams;
	CTAP_credParams pubKeyCredParams_chosen;
	CborValue excludeList;
	// extensions-specific:
	uint8_t credProtect;
} CTAP_makeCredential;
// On success, the authenticator returns the following authenticatorMakeCredential response structure
// which contains an attestation object plus additional information.
#define CTAP_makeCredential_res_fmt           0x01
#define CTAP_makeCredential_res_authData      0x02
#define CTAP_makeCredential_res_attStmt       0x03
#define CTAP_makeCredential_res_epAtt         0x04
#define CTAP_makeCredential_res_largeBlobKey  0x05

// 6.2. authenticatorGetAssertion (0x02)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetAssertion
// This method is invoked by the host to request generation of a new credential in the authenticator.
// It takes the following input parameters, several of which correspond
// to those defined in the authenticatorMakeCredential operation section
// of the Web Authentication specification:
#define CTAP_getAssertion_rpId                   0x01
#define CTAP_getAssertion_clientDataHash         0x02
#define CTAP_getAssertion_allowList              0x03
#define CTAP_getAssertion_extensions             0x04
#define CTAP_getAssertion_options                0x05
#define CTAP_getAssertion_pinUvAuthParam         0x06
#define CTAP_getAssertion_pinUvAuthProtocol      0x07
typedef struct CTAP_getAssertion {
	CTAP_mc_ga_common common;
	CborValue allowList;
	// extensions-specific:
	CTAP_getAssertion_hmac_secret hmac_secret;
} CTAP_getAssertion;
// On success, the authenticator returns the following authenticatorGetAssertion response structure:
#define CTAP_getAssertion_res_credential           0x01
#define CTAP_getAssertion_res_authData             0x02
#define CTAP_getAssertion_res_signature            0x03
#define CTAP_getAssertion_res_user                 0x04
#define CTAP_getAssertion_res_numberOfCredentials  0x05
#define CTAP_getAssertion_res_userSelected         0x06
#define CTAP_getAssertion_res_largeBlobKey         0x07

// 6.5. authenticatorClientPIN (0x06) command
// 6.5.5. authenticatorClientPIN (0x06) Command Definition
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
typedef struct CTAP_clientPIN {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	uint8_t pinUvAuthProtocol; // optional
	uint8_t subCommand; // REQUIRED
	COSE_Key keyAgreement; // optional
	ctap_string_t pinUvAuthParam; // optional
	ctap_string_t newPinEnc; // optional
	ctap_string_t pinHashEnc; // optional
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

// 6.8. authenticatorCredentialManagement (0x0A)
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement
typedef struct CTAP_credentialManagement_subCmdParams {
	const uint8_t *raw; // not a param, pointer to the raw bytes of the CBOR map
	size_t raw_size; // not a param, size (in bytes) of the CBOR-encoded raw data
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	ctap_string_t rpIDHash; // SHA-256 digest (32 bytes)
	CTAP_credDesc credentialID;
	CTAP_userEntity user;
} CTAP_credentialManagement_subCmdParams;
#define CTAP_credentialManagement_subCommandParams_rpIDHash      0x01
#define CTAP_credentialManagement_subCommandParams_credentialID  0x02
#define CTAP_credentialManagement_subCommandParams_user          0x03
typedef struct CTAP_credentialManagement {
	uint32_t present; // not a param, holds parsing info (if param was parsed, i.e., present)
	uint8_t subCommand;
	CTAP_credentialManagement_subCmdParams subCommandParams;
	uint8_t pinUvAuthProtocol;
	ctap_string_t pinUvAuthParam;
} CTAP_credentialManagement;
// 6.5.5. authenticatorClientPIN (0x06) Command Definition
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-cmd-dfn
// The command takes the following input parameters:
#define CTAP_credentialManagement_subCommand                     0x01
#define CTAP_credentialManagement_subCommandParams               0x02
#define CTAP_credentialManagement_pinUvAuthProtocol              0x03
#define CTAP_credentialManagement_pinUvAuthParam                 0x04
// The list of sub commands for credential management is:
#define CTAP_credentialManagement_subCmd_getCredsMetadata                       0x01
#define CTAP_credentialManagement_subCmd_enumerateRPsBegin                      0x02
#define CTAP_credentialManagement_subCmd_enumerateRPsGetNextRP                  0x03
#define CTAP_credentialManagement_subCmd_enumerateCredentialsBegin              0x04
#define CTAP_credentialManagement_subCmd_enumerateCredentialsGetNextCredential  0x05
#define CTAP_credentialManagement_subCmd_deleteCredential                       0x06
#define CTAP_credentialManagement_subCmd_updateUserInformation                  0x07
// On success, authenticator returns the following structure in its response:
#define CTAP_credentialManagement_res_existingResidentCredentialsCount              0x01
#define CTAP_credentialManagement_res_maxPossibleRemainingResidentCredentialsCount  0x02
#define CTAP_credentialManagement_res_rp                                            0x03
#define CTAP_credentialManagement_res_rpIDHash                                      0x04
#define CTAP_credentialManagement_res_totalRPs                                      0x05
#define CTAP_credentialManagement_res_user                                          0x06
#define CTAP_credentialManagement_res_credentialID                                  0x07
#define CTAP_credentialManagement_res_publicKey                                     0x08
#define CTAP_credentialManagement_res_totalCredentials                              0x09
#define CTAP_credentialManagement_res_credProtect                                   0x0A
#define CTAP_credentialManagement_res_largeBlobKey                                  0x0B

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

typedef struct ctap_parse_pub_key_cred_desc_list_ctx {
	CborValue it;
	size_t length;
	size_t next_idx;
	CTAP_credDesc item;
} ctap_parse_pub_key_cred_desc_list_ctx;

uint8_t ctap_parse_pub_key_cred_desc_list_init(
	ctap_parse_pub_key_cred_desc_list_ctx *ctx,
	const CborValue *list
);

uint8_t ctap_parse_pub_key_cred_desc_list_next_cred(
	ctap_parse_pub_key_cred_desc_list_ctx *ctx,
	CTAP_credDesc **cred_desc
);

uint8_t ctap_parse_make_credential(CborValue *it, CTAP_makeCredential *params);

bool ctap_is_supported_pub_key_cred_alg(const CTAP_credParams *cred_params);

uint8_t ctap_parse_make_credential_pub_key_cred_params(CTAP_makeCredential *params);

uint8_t ctap_parse_get_assertion(CborValue *it, CTAP_getAssertion *params);

uint8_t ctap_parse_credential_management(CborValue *it, CTAP_credentialManagement *cm);

#endif // LIONKEY_CTAP_PARSE_H
