#include "ctap_pin.h"
#include "utils.h"
#include <uECC.h>
#include <hmac.h>
#include <aes.h>

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

static int ctap_add_cose_key(
	CborEncoder *encoder,
	uint8_t *x,
	uint8_t *y,
	uint8_t credtype,
	int32_t algtype
) {

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, algtype != COSE_ALG_EDDSA ? 5 : 4));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_KTY));
	cbor_encoding_check(cbor_encode_int(&map, algtype != COSE_ALG_EDDSA ? COSE_KEY_KTY_EC2 : COSE_KEY_KTY_OKP));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_ALG));
	cbor_encoding_check(cbor_encode_int(&map, algtype));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_CRV));
	cbor_encoding_check(cbor_encode_int(&map, algtype != COSE_ALG_EDDSA ? COSE_KEY_CRV_P256 : COSE_KEY_CRV_ED25519));

	cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_X));
	cbor_encoding_check(cbor_encode_byte_string(&map, x, 32));

	if (algtype != COSE_ALG_EDDSA) {
		cbor_encoding_check(cbor_encode_int(&map, COSE_KEY_LABEL_Y));
		cbor_encoding_check(cbor_encode_byte_string(&map, y, 32));
	}

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

uint8_t ctap_client_pin_set_pin(ctap_state_t *state, const CTAP_clientPIN *cp) {

	// 6.5.5.5 Setting a New PIN

	// 5.1 If the authenticator does not receive mandatory parameters for this command,
	//     it returns CTAP2_ERR_MISSING_PARAMETER error.
	if (!cp->keyAgreementPresent || cp->newPinEncSize == 0 || cp->pinUvAuthParamSize == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	// 5.3 If a PIN has already been set, authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error.
	// TODO: re-enable this check
	// if (state->persistent.is_pin_set == 1) {
	// 	return CTAP2_ERR_PIN_AUTH_INVALID;
	// }

	// 5.4 The authenticator calls decapsulate on the provided platform key-agreement key
	//     to obtain the shared secret. If an error results, it returns CTAP1_ERR_INVALID_PARAMETER.
	//
	// decapsulate(peerCoseKey) → sharedSecret | error
	//   1. Return ecdh(peerCoseKey).
	//
	// ecdh(peerCoseKey) → sharedSecret | error
	//   1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
	//      If unsuccessful, or if the resulting point is not on the curve, return error.
	//   2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
	//      with the local private key agreement key.)
	//   3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
	//   4. Return kdf(Z).
	//
	// kdf(Z) → sharedSecret
	//   Return SHA-256(Z).
	//
	uint8_t shared_secret[32];
	if (uECC_shared_secret(
		(uint8_t *) &cp->keyAgreement.pubkey,
		state->KEY_AGREEMENT_PRIV,
		shared_secret,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_shared_secret failed" nl);
		return CTAP1_ERR_INVALID_PARAMETER;
	}
	SHA256_CTX sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, shared_secret, 32);
	sha256_final(&sha256_ctx, shared_secret);

	// 5.5 The authenticator calls verify(shared secret, newPinEnc, pinUvAuthParam)
	//     If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	//
	// verify(key, message, signature) → success | error
	//   Verifies that the signature is a valid MAC for the given message.
	//   If the key parameter value is the current pinUvAuthToken,
	//   it also checks whether the pinUvAuthToken is in use or not.
	//
	// verify(key, message, signature) → success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.

	// verify(key = shared secret, message = newPinEnc, signature = pinUvAuthParam)
	uint8_t hmac[32];
	hmac_sha256_ctx_t hmac_sha256_ctx;
	hmac_sha256_init(&hmac_sha256_ctx, shared_secret, 32);
	hmac_sha256_update(&hmac_sha256_ctx, cp->newPinEnc, cp->newPinEncSize);
	hmac_sha256_final(&hmac_sha256_ctx, hmac);
	if (cp->pinUvAuthParamSize != 16 || memcmp(hmac, cp->pinUvAuthParam, 16) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}

	// 5.6 The authenticator calls decrypt(shared secret, newPinEnc) to produce paddedNewPin.
	//     If an error results, it returns CTAP2_ERR_PIN_AUTH_INVALID.
	if (cp->newPinEncSize != 64) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	uint8_t all_zero_iv[AES_BLOCKLEN];
	memset(all_zero_iv, 0, AES_BLOCKLEN);
	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, shared_secret, all_zero_iv);
	uint8_t padded_new_pin[64];
	memcpy(padded_new_pin, cp->newPinEnc, 64);
	AES_CBC_decrypt_buffer(&aes_ctx, padded_new_pin, 64);

	// 5.7 If paddedNewPin is NOT 64 bytes long, it returns CTAP1_ERR_INVALID_PARAMETER

	// 5.8 The authenticator drops all trailing 0x00 bytes from paddedNewPin to produce newPin.
	uint8_t *new_pin;
	size_t new_pin_length = 0;
	for (size_t i = 0; i < 64; ++i) {
		if (padded_new_pin[i] != 0x00) {
			new_pin = &padded_new_pin[i];
			new_pin_length = 64 - i;
		}
	}

	// 5.9 The authenticator checks the length of newPin against the current minimum PIN length,
	//     returning CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
	// 5.10 An authenticator MAY impose arbitrary, additional constraints on PINs.
	//      If newPin fails to satisfy such additional constraints,
	//      the authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION.
	// TODO

	// 5.11 Authenticator remembers newPin length internally as PINCodePointLength.
	// 5.12 Authenticator stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN,
	//      sets the pinRetries counter to maximum count, and returns CTAP2_OK.
	// TODO

	return CTAP2_OK;

}

uint8_t ctap_client_pin(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
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
			// start response map
			cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 1));
			// 1. keyAgreement
			cbor_encoding_check(cbor_encode_int(&map, CTAP_clientPIN_res_keyAgreement));
			if (uECC_compute_public_key(
				state->KEY_AGREEMENT_PRIV,
				state->KEY_AGREEMENT_PUB,
				uECC_secp256r1()
			) != 1) {
				error_log("uECC_compute_public_key failed" nl);
				return CTAP1_ERR_OTHER;
			}
			if ((
					ret = ctap_add_cose_key(
						&map,
						state->KEY_AGREEMENT_PUB,
						state->KEY_AGREEMENT_PUB + 32,
						0,
						COSE_ALG_ECDH_ES_HKDF_256
					)) != CTAP2_OK) {
				return ret;
			}
			// close response map
			cbor_encoding_check(cbor_encoder_close_container(encoder, &map));
			break;

		case CTAP_clientPIN_subCmd_setPIN:
			return ctap_client_pin_set_pin(state, &cp);
			break;

		default:
			return CTAP2_ERR_INVALID_SUBCOMMAND;

	}

	return CTAP2_OK;

}
