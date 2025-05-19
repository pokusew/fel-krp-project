#ifndef LIONKEY_STM32H33_CRYPTO_H
#define LIONKEY_STM32H33_CRYPTO_H

#include "ctap_crypto.h"
#include "stm32h5xx_hal.h"

typedef struct stm32h533_crypto_context {
	RNG_HandleTypeDef hal_rng;
	PKA_HandleTypeDef hal_pka;
	CRYP_HandleTypeDef hal_cryp;
	HASH_HandleTypeDef hal_hash;
} stm32h533_crypto_context_t;

#define STM32H533_CRYPTO_CONST_INIT(context_ptr) \
    { \
        .context = (context_ptr), \
        .init = stm32h533_crypto_init, \
        .rng_init = stm32h533_crypto_rng_init, \
        .rng_generate_data = stm32h533_crypto_rng_generate_data, \
        .ecc_secp256r1_compute_public_key = stm32h533_crypto_ecc_secp256r1_compute_public_key, \
        .ecc_secp256r1_sign = stm32h533_crypto_ecc_secp256r1_sign, \
        .ecc_secp256r1_shared_secret = stm32h533_crypto_ecc_secp256r1_shared_secret, \
        .aes_256_cbc_encrypt = stm32h533_crypto_aes_256_cbc_encrypt, \
        .aes_256_cbc_decrypt = stm32h533_crypto_aes_256_cbc_decrypt, \
        .sha256_bind_ctx = stm32h533_crypto_sha256_bind_ctx, \
        .sha256_compute_digest = stm32h533_crypto_sha256_compute_digest, \
        .sha256 = &hash_alg_hw_sha256, \
    }

ctap_crypto_status_t stm32h533_crypto_init(
	const ctap_crypto_t *crypto,
	uint32_t seed
);

ctap_crypto_status_t stm32h533_crypto_rng_init(
	const ctap_crypto_t *crypto,
	uint32_t seed
);

ctap_crypto_status_t stm32h533_crypto_rng_generate_data(
	const ctap_crypto_t *crypto,
	uint8_t *buffer,
	size_t length
);

ctap_crypto_status_t stm32h533_crypto_ecc_secp256r1_compute_public_key(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	uint8_t *public_key
);

ctap_crypto_status_t stm32h533_crypto_ecc_secp256r1_sign(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	const uint8_t *message_hash,
	size_t message_hash_size,
	uint8_t *signature,
	const uint8_t *optional_fixed_k
);

ctap_crypto_status_t stm32h533_crypto_ecc_secp256r1_shared_secret(
	const ctap_crypto_t *crypto,
	const uint8_t *public_key,
	const uint8_t *private_key,
	uint8_t *secret
);

ctap_crypto_status_t stm32h533_crypto_aes_256_cbc_encrypt(
	const ctap_crypto_t *crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	size_t data_length
);

ctap_crypto_status_t stm32h533_crypto_aes_256_cbc_decrypt(
	const ctap_crypto_t *crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	size_t data_length
);

ctap_crypto_status_t stm32h533_crypto_sha256_bind_ctx(
	const ctap_crypto_t *crypto,
	void *sha256_ctx
);

ctap_crypto_status_t stm32h533_crypto_sha256_compute_digest(
	const ctap_crypto_t *crypto,
	const uint8_t *data, size_t data_length,
	uint8_t *hash
);

#endif // LIONKEY_STM32H33_CRYPTO_H
