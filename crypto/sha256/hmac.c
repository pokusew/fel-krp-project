#include <string.h>
#include <assert.h>
#include "hmac.h"

void hmac_sha256_init(hmac_sha256_ctx_t *const ctx, const uint8_t *const key, const size_t key_length) {

	// https://en.wikipedia.org/wiki/HMAC#Definition
	// https://en.wikipedia.org/wiki/HMAC#Implementation

	// compute the block sized key
	uint8_t block_sized_key[sizeof(ctx->i_o_key_pad)];
	static_assert(
		sizeof(block_sized_key) == sizeof(ctx->i_o_key_pad),
		"sizeof(block_sized_key) == sizeof(ctx->i_o_key_pad)"
	);

	// keys longer than blockSize are shortened by hashing them
	if (key_length > sizeof(block_sized_key)) {
		// we can avoid additional SHA256_CTX instance by using the one in the ctx
		sha256_init(&ctx->sha256_ctx);
		sha256_update(&ctx->sha256_ctx, key, key_length);
		sha256_final(&ctx->sha256_ctx, block_sized_key);
		// SHA256 output is 32 bytes, pad with zeros on the right
		memset(&block_sized_key[32], 0, 32);
	} else {
		if (key_length > 0) {
			assert(key != NULL);
			memcpy(block_sized_key, key, key_length);
		}
		// keys shorter than blockSize are padded to blockSize by padding with zeros on the right
		if (key_length < sizeof(block_sized_key)) {
			memset(&block_sized_key[key_length], 0, sizeof(block_sized_key) - key_length);
		}
	}

	// compute the inner padded key and store it in the ctx->i_o_key_pad
	for (size_t i = 0; i < sizeof(block_sized_key); i++) {
		ctx->i_o_key_pad[i] = block_sized_key[i] ^ 0x36u;
	}

	// start computing hash(i_key_pad || data...
	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->i_o_key_pad, sizeof(ctx->i_o_key_pad));

	// compute the outer padded key and store it in the ctx->i_o_key_pad
	// so that it can be used by hmac_sha256_final
	for (size_t i = 0; i < sizeof(block_sized_key); i++) {
		ctx->i_o_key_pad[i] = block_sized_key[i] ^ 0x5cu;
	}

}

void hmac_sha256_update(hmac_sha256_ctx_t *const ctx, const uint8_t *const data, const size_t data_length) {
	sha256_update(&ctx->sha256_ctx, data, data_length);
}

void hmac_sha256_final(hmac_sha256_ctx_t *const ctx, uint8_t *const hmac) {

	// finish computing the inner_hash (use the output hmac buffer as a temporary storage)
	// inner_hash = hash(i_key_pad || data... )
	sha256_final(&ctx->sha256_ctx, hmac);

	// compute hmac = hash(o_key_pad || inner_hash)
	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->i_o_key_pad, sizeof(ctx->i_o_key_pad)); // o_key_pad
	sha256_update(&ctx->sha256_ctx, hmac, LIONKEY_SHA256_OUTPUT_SIZE); // inner_hash
	sha256_final(&ctx->sha256_ctx, hmac); // hmac = hash(o_key_pad || inner_hash)

}
