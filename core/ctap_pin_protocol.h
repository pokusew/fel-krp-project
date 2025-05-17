#ifndef LIONKEY_CTAP_PIN_PROTOCOL_H
#define LIONKEY_CTAP_PIN_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "ctap_cbor.h"

#include "cose.h"
#include "ctap_pin_uv_auth_token_state.h"

#define CTAP_PIN_UV_AUTH_TOKEN_SIZE 32

/**
 * 6.5. authenticatorClientPIN (0x06)
 * 6.5.4. PIN/UV Auth Protocol Abstract Definition
 *
 * PIN/UV Auth Protocol exists so that plaintext PINs are not sent to the authenticator.
 * Instead, a PIN/UV auth protocol (aka pinUvAuthProtocol) ensures that PINs
 * are encrypted when sent to an authenticator and are exchanged for a pinUvAuthToken
 * that serves to authenticate subsequent commands.
 * Additionally, authenticators supporting built-in user verification methods
 * can provide a pinUvAuthToken upon user verification.
 * Note:
 *   PIN/UV Auth Protocol One was essentially defined in CTAP2.0.
 *   The difference between the original definition and the definition in CTAP2.1
 *   is that originally the pinToken (pinUvAuthToken in CTAP2.1 terms) length was unlimited.
 *   CTAP2.1 specifies lengths for pinUvAuthTokens
 *   in both PIN/UV Auth Protocol 1 and in PIN/UV Auth Protocol 2.
 */
typedef struct ctap_pin_protocol {

	uint8_t pin_uv_auth_token[CTAP_PIN_UV_AUTH_TOKEN_SIZE];
	uint8_t key_agreement_public_key[64];
	uint8_t key_agreement_private_key[32];

	const size_t version;
	const size_t shared_secret_length;
	const size_t encryption_extra_length;

	/**
	 * Initializes the protocol for use.
	 *
	 * This process is run by the authenticator at power-on.
	 *
	 * @see ctap_pin_protocol_initialize()
	 *
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const initialize)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Generates a fresh ECDH key agreement key pair (key_agreement_public_key, key_agreement_private_key).
	 *
	 * @see ctap_pin_protocol_regenerate()
	 *
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const regenerate)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Generates a fresh pinUvAuthToken.
	 *
	 * @see ctap_pin_protocol_reset_pin_uv_auth_token()
	 *
	 * @param protocol the protocol
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const reset_pin_uv_auth_token)(
		struct ctap_pin_protocol *protocol
	);

	/**
	 * Encodes the current key_agreement_public_key as a COSE_Key object into the given CBOR stream.
	 *
	 * @see ctap_pin_protocol_get_public_key()
	 *
	 * @param protocol the protocol
	 * @param encoder CBOR encoder
	 * @return a CTAP status code
	 * @retval CTAP1_ERR_OTHER when a CBOR encoding error occurs
	 * @retval CTAP2_OK when the COSE_Key was successfully encoded using the given CBOR encoder
	 */
	uint8_t (*const get_public_key)(
		struct ctap_pin_protocol *protocol,
		CborEncoder *encoder
	);

	/**
	 * Processes the output of encapsulate from the peer and produces a shared secret,
	 * known to both platform and authenticator.
	 *
	 * In other words, it computes a shared key (point) using the peer's public key (`peer_public_key`)
	 * and the authenticator's private key (`protocol.key_agreement_private_key`)
	 * using ECDH (Elliptic-curve Diffie-Hellman). It then derives the shared secret
	 * from the computed shared key (point) by calling protocol->kdf()
	 * (the exact algorithm varies between protocol versions).
	 *
	 * @see ctap_pin_protocol_decapsulate()
	 *
	 * @param protocol this
	 * @param peer_public_key the public key of the peer (the platform, resp. the client),
	 * @param [out] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                            (32 bytes for v1, 64 bytes for v2)
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const decapsulate)(
		const struct ctap_pin_protocol *protocol,
		const COSE_Key *peer_public_key,
		uint8_t *shared_secret
	);

	/**
	 * Derives a shared secret from an ECDH shared key (point).
	 *
	 * KDF = Key Derivation Function
	 *
	 * This method should not be called directly. It is called internally by decapsulate().
	 *
	 * @see ctap_pin_protocol_decapsulate()
	 * @see ctap_pin_protocol_v1_kdf()
	 * @see ctap_pin_protocol_v2_kdf()
	 *
	 * @param protocol this
	 * @param ecdh_shared_point_z the ECDH shared key (point), the result of an ECDH key agreement
	 * @param [out] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                            (32 bytes for v1, 64 bytes for v2)
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const kdf)(
		const struct ctap_pin_protocol *protocol,
		const uint8_t *ecdh_shared_point_z,
		uint8_t *shared_secret
	);

	/**
	 * Encrypts a plaintext using a shared secret as a key and outputs a ciphertext to the given ciphertext buffer.
	 *
	 * The plaintext remains unchanged.
	 *
	 * @see ctap_pin_protocol_v1_encrypt()
	 * @see ctap_pin_protocol_v2_encrypt()
	 *
	 * @param [in] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                           (32 bytes for v1, 64 bytes for v2)
	 * @param [in] plaintext the plaintext
	 * @param [in] plaintext_length the plaintext length in bytes
	 * @param [out] ciphertext the pointer to an array of size at least (plaintext_length + encryption_extra_length)
	 *                         bytes where the ciphertext will be written
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const encrypt)(
		const uint8_t *shared_secret,
		const uint8_t *plaintext, const size_t plaintext_length,
		uint8_t *ciphertext
	);

	/**
	 * Decrypts a ciphertext using a shared secret as a key and outputs a plaintext to the given plaintext buffer.
	 *
	 * The ciphertext remains unchanged.
	 *
	 * @see ctap_pin_protocol_v1_decrypt()
	 * @see ctap_pin_protocol_v2_decrypt()
	 *
	 * @param [in] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                           (32 bytes for v1, 64 bytes for v2)
	 * @param [in] ciphertext the ciphertext
	 * @param [in] ciphertext_length the ciphertext length in bytes
	 * @param [out] plaintext the pointer to an array of size at least (ciphertext_length - encryption_extra_length)
	 *                        bytes the plaintext will be written
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	int (*const decrypt)(
		const uint8_t *shared_secret,
		const uint8_t *ciphertext, const size_t ciphertext_length,
		uint8_t *plaintext
	);

	/**
	 * Returns the number of bytes needed to hold the verify context
	 *
	 * The caller can use this to allocate the context on the stack:
	 * ```
	 * uint8_t verify_ctx[pin_protocol->verify_get_context_size(pin_protocol)];
	 * ```
	 *
	 * The returned size is always greater than 0 so that the variable-length array allocation
	 * can be used (C standard does not allow variable-length arrays with zero length).
	 *
	 * @see ctap_pin_protocol_verify_get_context_size()
	 *
	 * @param [in] protocol the protocol
	 * @return the size (> 0) of the verify context in bytes
	 */
	size_t (*const verify_get_context_size)(const struct ctap_pin_protocol *protocol);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * Uses a shared secret as the HMAC key.
	 *
	 * @see ctap_pin_protocol_v1_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_v2_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_verify_init_with_pin_uv_auth_token()
	 * @see ctap_pin_protocol_verify_update()
	 * @see ctap_pin_protocol_v1_verify_final()
	 * @see ctap_pin_protocol_v2_verify_final()
	 *
	 * @param [in] protocol the protocol
	 * @param [in,out] ctx the pointer to the verify context that will be initialized by this call,
	 *                     the verify context must be an uint8_t array
	 *                     of pin_protocol->verify_get_context_size(pin_protocol) size,
	 * @param [in] shared_secret the shared secret, an array of `protocol.shared_secret_length` bytes
	 *                           (32 bytes for v1, 64 bytes for v2)
	 */
	void (*const verify_init_with_shared_secret)(
		const struct ctap_pin_protocol *protocol,
		void *ctx,
		const uint8_t *shared_secret
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * Uses the current pinUvAuthToken `protocol.pin_uv_auth_token` as the HMAC key.
	 * It also checks whether the pinUvAuthToken is in use or not.
	 * If the pinUvAuthToken is not in use, it returns an error.
	 *
	 * @see ctap_pin_protocol_v1_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_v2_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_verify_init_with_pin_uv_auth_token()
	 * @see ctap_pin_protocol_verify_update()
	 * @see ctap_pin_protocol_v1_verify_final()
	 * @see ctap_pin_protocol_v2_verify_final()
	 *
	 * @param [in] protocol the protocol
	 * @param [in,out] ctx the pointer to the verify context that will be initialized by this call,
	 *                     the verify context must be an uint8_t array
	 *                     of pin_protocol->verify_get_context_size(pin_protocol) size,
	 * @param [in,out] pin_uv_auth_token_state the pinUvAuthToken state (if valid, i.e., in_use == true,
	 *                                         its usage_timer.last_use will be updated to the current time
	 *                                         by this function)
	 * @retval 0 on success
	 * @retval 1 on error (the pinUvAuthToken is NOT in use)
	 */
	int (*const verify_init_with_pin_uv_auth_token)(
		const struct ctap_pin_protocol *protocol,
		void *ctx,
		ctap_pin_uv_auth_token_state *pin_uv_auth_token_state
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * This function might be called multiple times to pass the message in multiple chunks.
	 * When the message has zero length, this function does not have to be called at all
	 * (e.g., the following call sequence is completely correct: `verify_init_*() -> verify_final()`).
	 *
	 * @see ctap_pin_protocol_v1_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_v2_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_verify_init_with_pin_uv_auth_token()
	 * @see ctap_pin_protocol_verify_update()
	 * @see ctap_pin_protocol_v1_verify_final()
	 * @see ctap_pin_protocol_v2_verify_final()
	 *
	 * @param [in] protocol the protocol
	 * @param [in,out] verify_ctx the pointer to the verify context
	 *                            that has been already initialized by `verify_init_with_shared_secret()`
	 *                            or `verify_init_with_pin_uv_auth_token()`
	 * @param [in] message_data a chunk of the message
	 * @param [in] message_data_length the size of the chunk of the message
	 */
	void (*const verify_update)(
		const struct ctap_pin_protocol *protocol,
		void *ctx,
		const uint8_t *message_data, const size_t message_data_length
	);

	/**
	 * Verifies that the signature is a valid MAC for the given message.
	 *
	 * This function must be called only after the context has been initialized by `verify_init_*()`
	 * and the message (if non-zero length) has been passed by one or more `verify_update()` calls.
	 *
	 * @see ctap_pin_protocol_v1_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_v2_verify_init_with_shared_secret()
	 * @see ctap_pin_protocol_verify_init_with_pin_uv_auth_token()
	 * @see ctap_pin_protocol_verify_update()
	 * @see ctap_pin_protocol_v1_verify_final()
	 * @see ctap_pin_protocol_v2_verify_final()
	 *
	 * @param [in] protocol the protocol
	 * @param [in,out] verify_ctx the pointer to the verify context
	 *                            that has been already initialized by `verify_init_with_shared_secret()`
	 *                            or `verify_init_with_pin_uv_auth_token()`
	 * @param [in] signature the signature
	 * @param [in] signature_length the signature length in bytes
	 * @retval 0 on success (the signature matches the computed HMAC-256 digest),
	 * @retval 1 on error (invalid signature length or the signature does NOT match the computed HMAC-256 digest)
	 */
	int (*const verify_final)(
		const struct ctap_pin_protocol *protocol,
		void *verify_ctx,
		const uint8_t *signature, const size_t signature_length
	);

} ctap_pin_protocol_t;

#define CTAP_PIN_PROTOCOL_V1_CONST_INIT \
    { \
        .version = 1, \
        .shared_secret_length = 32, \
        .encryption_extra_length = 0, \
        .initialize = ctap_pin_protocol_initialize, \
        .regenerate = ctap_pin_protocol_regenerate, \
        .reset_pin_uv_auth_token = ctap_pin_protocol_reset_pin_uv_auth_token, \
        .get_public_key = ctap_pin_protocol_get_public_key, \
        .decapsulate = ctap_pin_protocol_decapsulate, \
        .kdf = ctap_pin_protocol_v1_kdf, \
        .encrypt = ctap_pin_protocol_v1_encrypt, \
        .decrypt = ctap_pin_protocol_v1_decrypt, \
        .verify_get_context_size = ctap_pin_protocol_verify_get_context_size, \
        .verify_init_with_shared_secret = ctap_pin_protocol_v1_verify_init_with_shared_secret, \
        .verify_init_with_pin_uv_auth_token = ctap_pin_protocol_verify_init_with_pin_uv_auth_token, \
        .verify_update = ctap_pin_protocol_verify_update, \
        .verify_final = ctap_pin_protocol_v1_verify_final, \
    }

#define CTAP_PIN_PROTOCOL_V2_CONST_INIT \
    { \
        .version = 2, \
        .shared_secret_length = 64, \
        .encryption_extra_length = 16, \
        .initialize = ctap_pin_protocol_initialize, \
        .regenerate = ctap_pin_protocol_regenerate, \
        .reset_pin_uv_auth_token = ctap_pin_protocol_reset_pin_uv_auth_token, \
        .get_public_key = ctap_pin_protocol_get_public_key, \
        .decapsulate = ctap_pin_protocol_decapsulate, \
        .kdf = ctap_pin_protocol_v2_kdf, \
        .encrypt = ctap_pin_protocol_v2_encrypt, \
        .decrypt = ctap_pin_protocol_v2_decrypt,    \
        .verify_get_context_size = ctap_pin_protocol_verify_get_context_size, \
		.verify_init_with_shared_secret = ctap_pin_protocol_v2_verify_init_with_shared_secret, \
        .verify_init_with_pin_uv_auth_token = ctap_pin_protocol_verify_init_with_pin_uv_auth_token, \
        .verify_update = ctap_pin_protocol_verify_update, \
        .verify_final = ctap_pin_protocol_v2_verify_final, \
    }

int ctap_pin_protocol_initialize(ctap_pin_protocol_t *protocol);

int ctap_pin_protocol_regenerate(ctap_pin_protocol_t *protocol);

int ctap_pin_protocol_reset_pin_uv_auth_token(ctap_pin_protocol_t *protocol);

uint8_t ctap_pin_protocol_get_public_key(ctap_pin_protocol_t *protocol, CborEncoder *encoder);

int ctap_pin_protocol_decapsulate(
	const ctap_pin_protocol_t *protocol,
	const COSE_Key *peer_public_key,
	uint8_t *shared_secret
);

int ctap_pin_protocol_v1_kdf(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *ecdh_shared_point_z,
	uint8_t *shared_secret
);

int ctap_pin_protocol_v2_kdf(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *ecdh_shared_point_z,
	uint8_t *shared_secret
);

int ctap_pin_protocol_v1_encrypt(
	const uint8_t *shared_secret,
	const uint8_t *plaintext, size_t plaintext_length,
	uint8_t *ciphertext
);

int ctap_pin_protocol_v2_encrypt(
	const uint8_t *shared_secret,
	const uint8_t *plaintext, size_t plaintext_length,
	uint8_t *ciphertext
);

int ctap_pin_protocol_v1_decrypt(
	const uint8_t *shared_secret,
	const uint8_t *ciphertext, size_t ciphertext_length,
	uint8_t *plaintext
);

int ctap_pin_protocol_v2_decrypt(
	const uint8_t *shared_secret,
	const uint8_t *ciphertext, size_t ciphertext_length,
	uint8_t *plaintext
);

size_t ctap_pin_protocol_verify_get_context_size(const ctap_pin_protocol_t *protocol);

void ctap_pin_protocol_v1_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	const uint8_t *shared_secret
);

void ctap_pin_protocol_v2_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	const uint8_t *shared_secret
);

int ctap_pin_protocol_verify_init_with_pin_uv_auth_token(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	ctap_pin_uv_auth_token_state *pin_uv_auth_token_state
);

void ctap_pin_protocol_verify_update(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	const uint8_t *message_data, size_t message_data_length
);

int ctap_pin_protocol_v1_verify_final(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	const uint8_t *signature, size_t signature_length
);

int ctap_pin_protocol_v2_verify_final(
	const ctap_pin_protocol_t *protocol,
	void *verify_ctx,
	const uint8_t *signature, size_t signature_length
);

#endif // LIONKEY_CTAP_PIN_PROTOCOL_H
