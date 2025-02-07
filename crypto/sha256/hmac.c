#include <string.h>
#include "hmac.h"

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_length) {

	// https://en.wikipedia.org/wiki/HMAC#Definition
	// https://en.wikipedia.org/wiki/HMAC#Implementation

	// compute the block sized key
	uint8_t block_sized_key[64];

	// keys longer than blockSize are shortened by hashing them
	if (key_length > 64) {
		// we can avoid additional SHA256_CTX instance by using the one in the ctx
		sha256_init(&ctx->sha256_ctx);
		sha256_update(&ctx->sha256_ctx, key, key_length);
		sha256_final(&ctx->sha256_ctx, block_sized_key);
		// SHA256 output is 32 bytes, pad with zeros on the right
		memset(&block_sized_key[32], 0, 32);
	}
	else {
		memcpy(block_sized_key, key, key_length);
		// keys shorter than blockSize are padded to blockSize by padding with zeros on the right
		if (key_length < 64) {
			memset(&block_sized_key[key_length], 0, 64 - key_length);
		}
	}

	// compute the inner padded key and store it in the ctx->i_o_key_pad
	for (size_t i = 0; i < 64; i++) {
		ctx->i_o_key_pad[i] = block_sized_key[i] ^ 0x36u;
	}

	// start computing hash(i_key_pad || data...
	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->i_o_key_pad, 64);

	// compute the outer padded key and store it in the ctx->i_o_key_pad
	// so that it can be used by hmac_sha256_final
	for (size_t i = 0; i < 64; i++) {
		ctx->i_o_key_pad[i] = block_sized_key[i] ^ 0x5cu;
	}

}

void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t length) {
	sha256_update(&ctx->sha256_ctx, data, length);
}

void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *hmac) {

	// finish computing the inner_hash (use the output hmac buffer as a temporary storage)
	// inner_hash = hash(i_key_pad || data... )
	sha256_final(&ctx->sha256_ctx, hmac);

	// compute hmac = hash(o_key_pad || inner_hash)
	sha256_init(&ctx->sha256_ctx);
	sha256_update(&ctx->sha256_ctx, ctx->i_o_key_pad, 64); // o_key_pad
	sha256_update(&ctx->sha256_ctx, hmac, 32); // inner_hash
	sha256_final(&ctx->sha256_ctx, hmac); // hmac = hash(o_key_pad || inner_hash)

}
