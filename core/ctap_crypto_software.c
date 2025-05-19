#include "ctap_crypto_software.h"
#include "compiler.h"

#include "aes.h"
#include <uECC.h>
#include <assert.h>

// verify that TinyAES is compiled with AES-256-CBC support
static_assert(TINYAES_AES_BLOCKLEN == CTAP_CRYPTO_AES_BLOCK_SIZE, "TINYAES_AES_BLOCKLEN == CTAP_CRYPTO_AES_BLOCK_SIZE");
static_assert(TINYAES_ENABLE_AES256 == 1, "unexpected TINYAES_ENABLE_AES256 value for AES-256-CBC");
static_assert(TINYAES_ENABLE_CBC == 1, "unexpected TINYAES_ENABLE_CBC value for AES-256-CBC");
static_assert(TINYAES_AES_KEYLEN == 32, "unexpected TINYAES_AES_KEYLEN value for AES-256-CBC");
static_assert(TINYAES_AES_KEYLEN == CTAP_CRYPTO_AES_256_KEY_SIZE, "TINYAES_AES_KEYLEN == CTAP_CRYPTO_AES_256_KEY_SIZE");

// Mersenne Twister Home Page
// https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/emt.html
// Tiny Mersenne Twister (TinyMT):
// https://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/TINYMT/index.html
// See also:
//   https://stackoverflow.com/questions/922358/consistent-pseudo-random-numbers-across-platforms
//   https://stackoverflow.com/questions/34903356/c11-random-number-distributions-are-not-consistent-across-platforms-what-al
//   -> Based on those discussions, the C++11 mt19937 should deliver consistent results across all platforms.
//      Note that if for some reason it stopped working, we would notice in our CI.

static int micro_ecc_compatible_rng(void *ctx, uint8_t *dest, unsigned size) {
	const ctap_crypto_t *const crypto = ctx;
	ctap_crypto_status_t status = crypto->rng_generate_data(crypto, dest, size);
	// translate the status to the uECC-compatible return value
	return status == CTAP_CRYPTO_OK ? 1 : 0;
}

ctap_crypto_status_t ctap_software_crypto_init(
	const ctap_crypto_t *const crypto,
	uint32_t seed
) {
	return crypto->rng_init(crypto, seed);
}

ctap_crypto_status_t ctap_software_crypto_rng_init(
	const ctap_crypto_t *const crypto,
	uint32_t seed
) {
	ctap_software_crypto_context_t *const ctx = crypto->context;
	tinymt32_init(&ctx->tinymt32_ctx, seed);
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t ctap_software_crypto_rng_generate_data(
	const ctap_crypto_t *const crypto,
	uint8_t *const buffer,
	const size_t length
) {
	ctap_software_crypto_context_t *const ctx = crypto->context;
	tinymt32_t *const tinymt32_ctx = &ctx->tinymt32_ctx;

	uint32_t word;
	uint8_t *const word_bytes = (uint8_t *) &word;

	size_t i = 0;

	// full 32-bit words
	for (size_t next_length = 4; next_length <= length; i += 4, next_length += 4, ++word) {
		// We use lion_htole32() here to get consistent results independent of the target endianness.
		// When the target is little-endian (most targets are), the lion_htole32() macro does nothing.
		word = lion_htole32(tinymt32_generate_uint32(tinymt32_ctx));
		buffer[i + 0] = word_bytes[0];
		buffer[i + 1] = word_bytes[1];
		buffer[i + 2] = word_bytes[2];
		buffer[i + 3] = word_bytes[3];
	}

	// remaining bytes (less than one 32-bit word, i.e., less than 4 bytes)
	if (i < length) {
		assert((length - i) < 4);
		word = lion_htole32(tinymt32_generate_uint32(tinymt32_ctx));
		for (size_t j = 0; i < length; ++i, ++j) {
			buffer[i] = word_bytes[j];
		}
	}

	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t ctap_software_crypto_ecc_secp256r1_compute_public_key(
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

// uECC does not include this declaration in its header file
// because this function is not part of the public API (it is intended for testing only)
// (the functions is not declared as static, so it is possible to use with explicit declaration)
int uECC_sign_with_k(
	const uint8_t *private_key,
	const uint8_t *message_hash,
	unsigned hash_size,
	const uint8_t *k,
	uint8_t *signature,
	uECC_Curve curve,
	uECC_RNG_Function g_rng_function,
	void *g_rng_function_ctx
);

ctap_crypto_status_t ctap_software_crypto_ecc_secp256r1_sign(
	const ctap_crypto_t *const crypto,
	const uint8_t *const private_key,
	const uint8_t *const message_hash,
	const size_t message_hash_size,
	uint8_t *const signature,
	const uint8_t *const optional_fixed_k
) {
	if (optional_fixed_k != NULL) {
		if (uECC_sign_with_k(
			private_key,
			message_hash,
			message_hash_size,
			optional_fixed_k,
			signature,
			uECC_secp256r1(),
			micro_ecc_compatible_rng,
			(void *) crypto
		) != 1) {
			return CTAP_CRYPTO_ERROR;
		}
		return CTAP_CRYPTO_OK;
	}
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

ctap_crypto_status_t ctap_software_crypto_ecc_secp256r1_shared_secret(
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

ctap_crypto_status_t ctap_software_crypto_aes_256_cbc_encrypt(
	const ctap_crypto_t *const crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	const size_t data_length
) {
	lion_unused(crypto);
	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, iv);
	AES_CBC_encrypt_buffer(&aes_ctx, data, data_length);
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t ctap_software_crypto_aes_256_cbc_decrypt(
	const ctap_crypto_t *const crypto,
	const uint8_t *iv,
	const uint8_t *key,
	uint8_t *data,
	const size_t data_length
) {
	lion_unused(crypto);
	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, iv);
	AES_CBC_decrypt_buffer(&aes_ctx, data, data_length);
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t ctap_software_crypto_sha256_bind_ctx(
	const ctap_crypto_t *crypto,
	void *hash_ctx
) {
	lion_unused(crypto);
	lion_unused(hash_ctx);
	return CTAP_CRYPTO_OK;
}

ctap_crypto_status_t ctap_software_crypto_sha256_compute_digest(
	const ctap_crypto_t *crypto,
	const uint8_t *data, size_t data_length,
	uint8_t *hash
) {
	lion_unused(crypto);
	sha256_ctx_t ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, data_length);
	sha256_final(&ctx, hash);
	// equivalently (but with the dereferencing overhead)
	// const hash_alg_t *const sha256 = crypto->sha256;
	// uint8_t ctx[sha256->ctx_size];
	// sha256->init(ctx);
	// sha256->update(ctx, data, data_length);
	// sha256->final(ctx, hash);
	return CTAP_CRYPTO_OK;
}
