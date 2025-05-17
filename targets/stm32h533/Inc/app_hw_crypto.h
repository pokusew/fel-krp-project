#ifndef LIONKEY_STM32H33_APP_HW_CRYPTO_H
#define LIONKEY_STM32H33_APP_HW_CRYPTO_H

#include "ctap_crypto.h"
#include "stm32h5xx_hal.h"
#include <sha256.h>
#include <tinymt32.h>

typedef struct app_hw_crypto_context {
	tinymt32_t tinymt32_ctx;
	CRYP_HandleTypeDef hal_cryp;
} app_hw_crypto_context_t;

#define APP_HW_CRYPTO_CONST_INIT(context_ptr) \
    { \
        .context = (context_ptr), \
        .init = app_hw_crypto_init, \
        .rng_init = app_hw_crypto_rng_init, \
        .rng_generate_data = app_hw_crypto_rng_generate_data, \
        .ecc_secp256r1_compute_public_key = app_hw_crypto_ecc_secp256r1_compute_public_key, \
        .ecc_secp256r1_sign = app_hw_crypto_ecc_secp256r1_sign, \
        .ecc_secp256r1_shared_secret = app_hw_crypto_ecc_secp256r1_shared_secret, \
        .aes_256_cbc_encrypt = app_hw_crypto_aes_256_cbc_encrypt, \
        .aes_256_cbc_decrypt = app_hw_crypto_aes_256_cbc_decrypt, \
        .sha256_context_size = sizeof(sha256_ctx_t), \
        .sha256_init = app_hw_crypto_sha256_init, \
        .sha256_update = app_hw_crypto_sha256_update, \
        .sha256_final = app_hw_crypto_sha256_final, \
        .sha256_compute_digest = app_hw_crypto_sha256_compute_digest, \
        .sha256 = &hash_alg_sha256, \
    }

ctap_crypto_status_t app_hw_crypto_init(
	const ctap_crypto_t *crypto,
	uint32_t seed
);

ctap_crypto_status_t app_hw_crypto_rng_init(
	const ctap_crypto_t *crypto,
	uint32_t seed
);

ctap_crypto_status_t app_hw_crypto_rng_generate_data(
	const ctap_crypto_t *crypto,
	uint8_t *buffer,
	size_t length
);

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_compute_public_key(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	uint8_t *public_key
);

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_sign(
	const ctap_crypto_t *crypto,
	const uint8_t *private_key,
	const uint8_t *message_hash,
	size_t message_hash_size,
	uint8_t *signature
);

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_shared_secret(
	const ctap_crypto_t *crypto,
	const uint8_t *public_key,
	const uint8_t *private_key,
	uint8_t *secret
);

ctap_crypto_status_t app_hw_crypto_aes_256_cbc_encrypt(
	const ctap_crypto_t *crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	size_t data_length
);

ctap_crypto_status_t app_hw_crypto_aes_256_cbc_decrypt(
	const ctap_crypto_t *crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	size_t data_length
);

ctap_crypto_status_t app_hw_crypto_sha256_init(
	const ctap_crypto_t *crypto,
	void *ctx
);

ctap_crypto_status_t app_hw_crypto_sha256_update(
	const ctap_crypto_t *crypto,
	void *ctx,
	const uint8_t *data, size_t data_length
);

ctap_crypto_status_t app_hw_crypto_sha256_final(
	const ctap_crypto_t *crypto,
	void *ctx,
	uint8_t *hash
);

ctap_crypto_status_t app_hw_crypto_sha256_compute_digest(
	const ctap_crypto_t *crypto,
	const uint8_t *data, size_t data_length,
	uint8_t *hash
);

#endif // LIONKEY_STM32H33_APP_HW_CRYPTO_H
