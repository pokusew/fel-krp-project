#include "ctap_pin.h"

// 6.5.4. PIN/UV Auth Protocol Abstract Definition

// A specific PIN/UV auth protocol defines an implementation of two interfaces to cryptographic services:
// one for the authenticator, and one for the platform.
//
// The authenticator interface is:

/// This process is run by the authenticator at power-on.
static void initialize();

/// Generates a fresh public key.
static void regenerate();

/// Generates a fresh pinUvAuthToken.
static void resetPinUvAuthToken();

/// Returns the authenticator’s public key as a COSE_Key structure.
static void getPublicKey(COSE_Key *cose_key);

/// Processes the output of encapsulate from the peer and produces a shared secret,
/// known to both platform and authenticator.
static uint8_t decapsulate(const uint8_t *peer_cose_key, uint8_t *shared_secret);

/// Decrypts a ciphertext, using sharedSecret as a key, and returns the plaintext.
static uint8_t decrypt(const uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *plaintext);

/// Verifies that the signature is a valid MAC for the given message.
/// If the key parameter value is the current pinUvAuthToken,
/// it also checks whether the pinUvAuthToken is in use or not.
static uint8_t verify(const uint8_t *key, const uint8_t *message, const uint8_t *signature);


// The platform interface is:
//
// initialize()
// This is run by the platform when starting a series of transactions with a specific authenticator.
//
// encapsulate(peerCoseKey) → (coseKey, sharedSecret) | error
// Generates an encapsulation for the authenticator’s public key and returns the message to transmit and the shared secret.
//
// encrypt(key, demPlaintext) → ciphertext
// Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
//
// decrypt(key, ciphertext) → plaintext | error
// Decrypts a ciphertext and returns the plaintext.
//
// authenticate(key, message) → signature
// Computes a MAC of the given message.

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length) {

	CborError err;

	CTAP_clientPIN cp;
	uint8_t status = ctap_parse_client_pin(request, length, &cp);
	if (status != CTAP2_OK) {
		return status;
	}

	if (cp.pinUvAuthProtocol != 1 && cp.pinUvAuthProtocol != 2) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	CborEncoder *encoder = &state->response.encoder;
	CborEncoder map;

	switch (cp.subCommand) {
		case CTAP_clientPIN_subCmd_getPINRetries:
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 2));
			// 1. pinRetries
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_pinRetries));
			cbor_encoding_check(cbor_encode_int(&map, state->persistent.pin_total_remaining_attempts));
			// 2. powerCycleState
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_powerCycleState));
			cbor_encoding_check(cbor_encode_boolean(&map, state->pin_boot_remaining_attempts > 0));
			// close response map
			cbor_encoding_check(cbor_encoder_close_container(encoder, &map));
			break;
		case CTAP_clientPIN_subCmd_getKeyAgreement:

			break;
		default:
			return CTAP2_ERR_INVALID_SUBCOMMAND;
	}

	return CTAP2_OK;

}
