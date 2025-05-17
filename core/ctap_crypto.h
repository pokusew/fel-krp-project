#ifndef LIONKEY_CTAP_CRYPTO
#define LIONKEY_CTAP_CRYPTO

#include <stddef.h>
#include <stdint.h>

#include <hash.h>

#define CTAP_CRYPTO_AES_BLOCK_SIZE 16
#define CTAP_CRYPTO_AES_256_KEY_SIZE 32

typedef enum ctap_crypto_status {
	CTAP_CRYPTO_OK = 0,
	CTAP_CRYPTO_ERROR = 1,
} ctap_crypto_status_t;

#define ctap_crypto_check(expr)                             \
	if ((expr) != CTAP_CRYPTO_OK) {                         \
		debug_log(                                          \
			red("ctap_crypto call failed at at %s:%d") nl,  \
			__FILE__, __LINE__                              \
		);                                                  \
		return CTAP1_ERR_OTHER;                             \
	}                                                       \
	((void) 0)

typedef struct ctap_crypto {

	void *context;

	/**
	 * Initializes the context
	 */
	ctap_crypto_status_t (*init)(
		const struct ctap_crypto *crypto,
		uint32_t seed
	);

	/**
	 * Initializes (or resets) the Random Number Generator with a given seed
	 */
	ctap_crypto_status_t (*rng_init)(
		const struct ctap_crypto *crypto,
		uint32_t seed
	);

	/**
	 * Generates random data using the Random Number Generator
	 */
	ctap_crypto_status_t (*rng_generate_data)(
		const struct ctap_crypto *crypto,
		uint8_t *buffer,
		size_t length
	);

	ctap_crypto_status_t (*ecc_secp256r1_compute_public_key)(
		const struct ctap_crypto *crypto,
		const uint8_t *private_key,
		uint8_t *public_key
	);

	ctap_crypto_status_t (*ecc_secp256r1_sign)(
		const struct ctap_crypto *crypto,
		const uint8_t *private_key,
		const uint8_t *message_hash,
		size_t message_hash_size,
		uint8_t *signature
	);

	ctap_crypto_status_t (*ecc_secp256r1_shared_secret)(
		const struct ctap_crypto *crypto,
		const uint8_t *public_key,
		const uint8_t *private_key,
		uint8_t *secret
	);

	/**
	 * Encrypts a plaintext using AES-256 in CBC mode
	 *
	 * @param [in] iv the AES-256 CBC initialization vector
	 * @param [in] key the AES-256 CBC key
	 * @param [in,out] data the plaintext, will encrypted in place to produce the ciphertext of the same length
	 * @param [in] data_length the plaintext/ciphertext length in bytes
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	ctap_crypto_status_t (*aes_256_cbc_encrypt)(
		const struct ctap_crypto *crypto,
		const uint8_t *iv,
		const uint8_t *key,
		uint8_t *data,
		const size_t data_length
	);

	/**
	 * Decrypts a ciphertext using AES-256 in CBC mode
	 *
	 * @param [in] iv the AES-256 CBC initialization vector
	 * @param [in] key the AES-256 CBC key
	 * @param [in,out] data the ciphertext, will decrypted in place to produce the plaintext of the same length
	 * @param [in] data_length the ciphertext/plaintext length in bytes
	 * @retval 0 on success
	 * @retval 1 on error
	 */
	ctap_crypto_status_t (*aes_256_cbc_decrypt)(
		const struct ctap_crypto *crypto,
		const uint8_t *iv,
		const uint8_t *key,
		uint8_t *data,
		const size_t data_length
	);

	ctap_crypto_status_t (*sha256_bind_ctx)(
		const struct ctap_crypto *crypto,
		void *sha256_ctx
	);

	ctap_crypto_status_t (*sha256_compute_digest)(
		const struct ctap_crypto *crypto,
		const uint8_t *data, size_t data_length,
		uint8_t *hash
	);

	const hash_alg_t *sha256;

} ctap_crypto_t;

#endif // LIONKEY_CTAP_CRYPTO
