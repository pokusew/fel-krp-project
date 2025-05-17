#include "app_hw_crypto.h"
#include "main.h"
#include "compiler.h"
#include "utils.h"

#include "aes.h"
#include <uECC.h>
#include <assert.h>
#include <string.h>

// verify that TinyAES is compiled with AES-256-CBC support
static_assert(TINYAES_AES_BLOCKLEN == CTAP_CRYPTO_AES_BLOCK_SIZE, "TINYAES_AES_BLOCKLEN == CTAP_CRYPTO_AES_BLOCK_SIZE");
static_assert(TINYAES_ENABLE_AES256 == 1, "unexpected TINYAES_ENABLE_AES256 value for AES-256-CBC");
static_assert(TINYAES_ENABLE_CBC == 1, "unexpected TINYAES_ENABLE_CBC value for AES-256-CBC");
static_assert(TINYAES_AES_KEYLEN == 32, "unexpected TINYAES_AES_KEYLEN value for AES-256-CBC");

// Mersenne Twister Home Page
// https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html
// Tiny Mersenne Twister (TinyMT):
// https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/TINYMT/index.html
// See also:
//   https://stackoverflow.com/questions/922358/consistent-pseudo-random-numbers-across-platforms
//   https://stackoverflow.com/questions/34903356/c11-random-number-distributions-are-not-consistent-across-platforms-what-al
//   -> Based on those discussions, the C++11 mt19937 should deliver consistent results across all platforms.
//      Note that if for some reason it stopped working, we would notice in our CI.

static ctap_crypto_status_t app_hw_crypto_aes_init(app_hw_crypto_context_t *ctx);

static ctap_crypto_status_t app_hw_crypto_hash_init(app_hw_crypto_context_t *ctx);

ctap_crypto_status_t app_hw_crypto_init(
	const ctap_crypto_t *const crypto,
	uint32_t seed
) {
	app_hw_crypto_context_t *const ctx = crypto->context;

	memset(ctx, 0, sizeof(app_hw_crypto_context_t));

	ctap_crypto_status_t status;

	status = crypto->rng_init(crypto, seed);
	if (status != CTAP_CRYPTO_OK) {
		return status;
	}

	status = app_hw_crypto_aes_init(ctx);
	if (status != CTAP_CRYPTO_OK) {
		return status;
	}

	return app_hw_crypto_hash_init(ctx);
}

static int micro_ecc_compatible_rng(void *ctx, uint8_t *dest, unsigned size) {
	const ctap_crypto_t *const crypto = ctx;
	ctap_crypto_status_t status = crypto->rng_generate_data(crypto, dest, size);
	// translate the status to the uECC-compatible return value
	return status == CTAP_CRYPTO_OK ? 1 : 0;
}

void HAL_CRYP_MspInit(CRYP_HandleTypeDef *hcryp) {
	if (hcryp->Instance == AES) {
		__HAL_RCC_AES_CLK_ENABLE();
	}
}

void HAL_CRYP_MspDeInit(CRYP_HandleTypeDef *hcryp) {
	if (hcryp->Instance == AES) {
		__HAL_RCC_AES_CLK_DISABLE();
	}
}

static ctap_crypto_status_t app_hw_crypto_aes_init(app_hw_crypto_context_t *const ctx) {

	CRYP_HandleTypeDef *const hal_cryp = &ctx->hal_cryp;

	hal_cryp->Instance = AES;
	// Note that the swapping configuration only applies to the data (writing AES_DINR and reading AES_DOUT),
	// but not to the IV and the key (AES_IVR0-3, AES_KEY0-7).
	hal_cryp->Init.DataType = CRYP_BYTE_SWAP;
	hal_cryp->Init.KeySize = CRYP_KEYSIZE_256B;
	//
	// hal_cryp->Init.pKey = (uint32_t *) NULL;
	// hal_cryp->Init.pInitVect = (uint32_t *) NULL;
	hal_cryp->Init.Algorithm = CRYP_AES_CBC;
	hal_cryp->Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
	hal_cryp->Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
	// When KeyIVConfigSkip == CRYP_KEYIVCONFIG_ONCE, the IV and the key are initialized
	// during first encryption/description call and hal_cryp->KeyIVConfig is set internally to 1U.
	// We want to use custom functions for initializing the IV and key (to perform byte swapping
	// without the need for extra copy). Therefore, we manually set the hal_cryp->KeyIVConfig to 1U.
	// Note that this must be done AFTER the HAL_CRYP_Init() call
	// (because HAL_CRYP_Init() sets hal_cryp->KeyIVConfig to 0U).
	hal_cryp->Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ONCE; // We hal_cryp->KeyIVConfig = 1U
	hal_cryp->Init.KeyMode = CRYP_KEYMODE_NORMAL;
	if (HAL_CRYP_Init(hal_cryp) != HAL_OK) {
		return CTAP_CRYPTO_ERROR;
	}
	// This ensures that the IV and key initialization are NEVER performed by the HAL.
	// We use custom functions that perform byte swapping efficiently.
	hal_cryp->KeyIVConfig = 1U;

	return CTAP_CRYPTO_OK;

}

ctap_crypto_status_t app_hw_crypto_rng_init(
	const ctap_crypto_t *const crypto,
	uint32_t seed
) {
	app_hw_crypto_context_t *const ctx = crypto->context;
	tinymt32_init(&ctx->tinymt32_ctx, seed);
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t app_hw_crypto_rng_generate_data(
	const ctap_crypto_t *const crypto,
	uint8_t *const buffer,
	const size_t length
) {
	app_hw_crypto_context_t *const ctx = crypto->context;
	tinymt32_t *const tinymt32_ctx = &ctx->tinymt32_ctx;
	uint32_t *word = (uint32_t *const) buffer;
	size_t i = 0;
	for (size_t next_length = 4; next_length <= length; i += 4, next_length += 4, ++word) {
		// We use lion_htole32() here to get consistent results independent of the target endianness.
		// When the target is little-endian (most targets are), the lion_htole32() macro does nothing.
		*word = lion_htole32(tinymt32_generate_uint32(tinymt32_ctx));
	}
	if (i < length) {
		assert((length - i) < 4);
		uint32_t last_word = lion_htole32(tinymt32_generate_uint32(tinymt32_ctx));
		uint8_t *last_word_bytes = (uint8_t *) &last_word;
		for (; i < length; ++i, ++last_word_bytes) {
			buffer[i] = *last_word_bytes;
		}
	}
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_compute_public_key(
	const ctap_crypto_t *const crypto,
	const uint8_t *const private_key,
	uint8_t *const public_key
) {
	if (uECC_compute_public_key(
		private_key,
		public_key,
		uECC_secp256r1(),
		micro_ecc_compatible_rng,
		(void *) crypto
	) != 1) {
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_sign(
	const ctap_crypto_t *const crypto,
	const uint8_t *const private_key,
	const uint8_t *const message_hash,
	const size_t message_hash_size,
	uint8_t *const signature
) {
	if (uECC_sign(
		private_key,
		message_hash,
		message_hash_size,
		signature,
		uECC_secp256r1(),
		micro_ecc_compatible_rng,
		(void *) crypto
	) != 1) {
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t app_hw_crypto_ecc_secp256r1_shared_secret(
	const ctap_crypto_t *const crypto,
	const uint8_t *const public_key,
	const uint8_t *const private_key,
	uint8_t *const secret
) {
	if (uECC_shared_secret(
		public_key,
		private_key,
		secret,
		uECC_secp256r1(),
		micro_ecc_compatible_rng,
		(void *) crypto
	) != 1) {
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

static void CRYP_AES_256_SetKey_Swap(CRYP_HandleTypeDef *hal_cryp, const uint32_t *key) {
	hal_cryp->Instance->KEYR7 = lion_bswap32(*(uint32_t *) (key));
	hal_cryp->Instance->KEYR6 = lion_bswap32(*(uint32_t *) (key + 1U));
	hal_cryp->Instance->KEYR5 = lion_bswap32(*(uint32_t *) (key + 2U));
	hal_cryp->Instance->KEYR4 = lion_bswap32(*(uint32_t *) (key + 3U));
	hal_cryp->Instance->KEYR3 = lion_bswap32(*(uint32_t *) (key + 4U));
	hal_cryp->Instance->KEYR2 = lion_bswap32(*(uint32_t *) (key + 5U));
	hal_cryp->Instance->KEYR1 = lion_bswap32(*(uint32_t *) (key + 6U));
	hal_cryp->Instance->KEYR0 = lion_bswap32(*(uint32_t *) (key + 7U));
}

static void CRYP_AES_256_SetIV_Swap(CRYP_HandleTypeDef *hal_cryp, const uint32_t *iv) {
	hal_cryp->Instance->IVR3 = lion_bswap32(*(uint32_t *) (iv));
	hal_cryp->Instance->IVR2 = lion_bswap32(*(uint32_t *) (iv + 1U));
	hal_cryp->Instance->IVR1 = lion_bswap32(*(uint32_t *) (iv + 2U));
	hal_cryp->Instance->IVR0 = lion_bswap32(*(uint32_t *) (iv + 3U));
}

#define CRYP_OPERATING_MODE_KEY_DERIVATION  AES_CR_MODE_0
#define CRYP_OPERATING_MODE_DECRYPT         AES_CR_MODE_1

// copied (slightly modified to match our code style) from stm32h5xx_hal_cryp.c
// (copied because it is defined as static, but we need for our custom CRYP_AES_256_CBC_SetDecryptKey())
static HAL_StatusTypeDef CRYP_WaitOnCCFlag(CRYP_HandleTypeDef *hal_cryp, uint32_t timeout) {
	uint32_t tick_start = HAL_GetTick();
	while (HAL_IS_BIT_CLR(hal_cryp->Instance->ISR, AES_ISR_CCF)) {
		if (timeout != HAL_MAX_DELAY) {
			if (((HAL_GetTick() - tick_start) > timeout) || (timeout == 0U)) {
				__HAL_CRYP_DISABLE(hal_cryp);
				hal_cryp->ErrorCode |= HAL_CRYP_ERROR_TIMEOUT;
				hal_cryp->State = HAL_CRYP_STATE_READY;
				__HAL_UNLOCK(hal_cryp);
				return HAL_ERROR;
			}
		}
	}
	return HAL_OK;
}

static HAL_StatusTypeDef CRYP_AES_256_CBC_SetDecryptKey(
	CRYP_HandleTypeDef *hal_cryp,
	const uint32_t *key,
	uint32_t timeout
) {
	// key preparation for decryption in CBC mode
	// see RM0481 33.4.9 AES basic chaining modes (ECB, CBC), ECB and CBC encryption process
	MODIFY_REG(hal_cryp->Instance->CR, AES_CR_KMOD, CRYP_KEYMODE_NORMAL);
	MODIFY_REG(hal_cryp->Instance->CR, AES_CR_MODE, CRYP_OPERATING_MODE_KEY_DERIVATION);
	CRYP_AES_256_SetKey_Swap(hal_cryp, key);
	__HAL_CRYP_ENABLE(hal_cryp);
	if (CRYP_WaitOnCCFlag(hal_cryp, timeout) != HAL_OK) {
		return HAL_ERROR;
	}
	__HAL_CRYP_CLEAR_FLAG(hal_cryp, CRYP_CLEAR_CCF);
	MODIFY_REG(hal_cryp->Instance->CR, AES_CR_MODE, CRYP_OPERATING_MODE_DECRYPT);
	return HAL_OK;
}

ctap_crypto_status_t app_hw_crypto_aes_256_cbc_encrypt(
	const ctap_crypto_t *const crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	const size_t data_length
) {
	if (data_length == 0) {
		return CTAP_CRYPTO_OK;
	}
	if (data_length % CTAP_CRYPTO_AES_BLOCK_SIZE) {
		return CTAP_CRYPTO_ERROR;
	}
	app_hw_crypto_context_t *const ctx = crypto->context;
	CRYP_HandleTypeDef *const hal_cryp = &ctx->hal_cryp;
	CRYP_AES_256_SetKey_Swap(hal_cryp, (const uint32_t *) key);
	CRYP_AES_256_SetIV_Swap(hal_cryp, (const uint32_t *) iv);
	HAL_StatusTypeDef status = HAL_CRYP_Encrypt(
		hal_cryp,
		(uint32_t *) data,
		data_length,
		(uint32_t *) data,
		HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("HAL_CRYP_Encrypt error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_cryp->ErrorCode
		);
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t app_hw_crypto_aes_256_cbc_decrypt(
	const ctap_crypto_t *const crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	const size_t data_length
) {
	if (data_length == 0) {
		return CTAP_CRYPTO_OK;
	}
	if (data_length % CTAP_CRYPTO_AES_BLOCK_SIZE) {
		return CTAP_CRYPTO_ERROR;
	}
	app_hw_crypto_context_t *const ctx = crypto->context;
	CRYP_HandleTypeDef *const hal_cryp = &ctx->hal_cryp;
	CRYP_AES_256_SetIV_Swap(hal_cryp, (const uint32_t *) iv);
	HAL_StatusTypeDef status = CRYP_AES_256_CBC_SetDecryptKey(
		hal_cryp, (const uint32_t *) key, HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("CRYP_AES_256_CBC_SetDecryptKey error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_cryp->ErrorCode
		);
		return CTAP_CRYPTO_ERROR;
	}
	status = HAL_CRYP_Decrypt(
		hal_cryp,
		(uint32_t *) data,
		data_length,
		(uint32_t *) data,
		HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("HAL_CRYP_Decrypt error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_cryp->ErrorCode
		);
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

void HAL_HASH_MspInit(HASH_HandleTypeDef *hhash) {
	lion_unused(hhash);
	__HAL_RCC_HASH_CLK_ENABLE();
}

void HAL_HASH_MspDeInit(HASH_HandleTypeDef *hhash) {
	lion_unused(hhash);
	__HAL_RCC_HASH_CLK_DISABLE();
}

static ctap_crypto_status_t app_hw_crypto_hash_init(app_hw_crypto_context_t *const ctx) {

	HASH_HandleTypeDef *const hal_hash = &ctx->hal_hash;

	hal_hash->Instance = HASH;
	hal_hash->Init.DataType = HASH_BYTE_SWAP;
	hal_hash->Init.Algorithm = HASH_ALGOSELECTION_SHA256;
	if (HAL_HASH_Init(hal_hash) != HAL_OK) {
		return CTAP_CRYPTO_ERROR;
	}

	return CTAP_CRYPTO_OK;

}

ctap_crypto_status_t app_hw_crypto_sha256_bind_ctx(
	const ctap_crypto_t *crypto,
	void *sha256_ctx
) {
	*((app_hw_crypto_context_t **) sha256_ctx) = crypto->context;
	// memcpy(sha256_ctx, &crypto->context, sizeof(app_hw_crypto_context_t *));
	return CTAP_CRYPTO_OK;
}

void app_hw_crypto_sha256_init(
	void *ctx
) {
	lion_unused(ctx);
}

void app_hw_crypto_sha256_update(
	void *ctx,
	const uint8_t *data, size_t data_length
) {
	HASH_HandleTypeDef *const hal_hash = &(*((app_hw_crypto_context_t **) ctx))->hal_hash;
	HAL_StatusTypeDef status = HAL_HASH_Accumulate(
		hal_hash,
		data, data_length,
		HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("HAL_HASH_Accumulate error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_hash->ErrorCode
		);
		Error_Handler();
	}
}

void app_hw_crypto_sha256_final(
	void *ctx,
	uint8_t *hash
) {
	HASH_HandleTypeDef *const hal_hash = &(*((app_hw_crypto_context_t **) ctx))->hal_hash;
	HAL_StatusTypeDef status = HAL_HASH_AccumulateLast(
		hal_hash,
		NULL, 0,
		hash,
		HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("HAL_HASH_AccumulateLast error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_hash->ErrorCode
		);
		Error_Handler();
	}
}

ctap_crypto_status_t app_hw_crypto_sha256_compute_digest(
	const ctap_crypto_t *crypto,
	const uint8_t *data, size_t data_length,
	uint8_t *hash
) {
	app_hw_crypto_context_t *const ctx = crypto->context;
	HASH_HandleTypeDef *const hal_hash = &ctx->hal_hash;
	HAL_StatusTypeDef status = HAL_HASH_Start(
		hal_hash,
		data, data_length,
		hash,
		HAL_MAX_DELAY
	);
	if (status != HAL_OK) {
		error_log(
			red("HAL_HASH_Start error: status = %d, ErrorCode = %" PRIx32) nl,
			status, hal_hash->ErrorCode
		);
		return CTAP_CRYPTO_ERROR;
	}
	return CTAP_CRYPTO_OK;
}

const hash_alg_t hash_alg_hw_sha256 = {
	.ctx_size = sizeof(app_hw_crypto_context_t *),
	.output_size = 32,
	.block_size = 64,
	.init = app_hw_crypto_sha256_init,
	.update = app_hw_crypto_sha256_update,
	.final = app_hw_crypto_sha256_final,
};
