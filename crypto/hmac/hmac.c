#include "hmac.h"
#include <string.h> // memset(), memcpy()
#include <assert.h>

typedef struct hmac_ctx {
	const hash_alg_t *hash_alg;
	void *hash_ctx;
} hmac_ctx_t;

size_t hmac_get_context_size(const hash_alg_t *const hash_alg) {
	return sizeof(hmac_ctx_t) + hash_alg->block_size;
}

void hmac_init(
	void *const ctx,
	const hash_alg_t *const hash_alg, void *const hash_ctx,
	const uint8_t *const key, const size_t key_length
) {

	hmac_ctx_t *const hmac_ctx = ctx;
	hmac_ctx->hash_alg = hash_alg;
	hmac_ctx->hash_ctx = hash_ctx;
	const size_t hash_block_size = hash_alg->block_size;

	uint8_t *i_o_key_pad = (uint8_t *) (hmac_ctx + 1);

	// https://en.wikipedia.org/wiki/HMAC#Definition
	// https://en.wikipedia.org/wiki/HMAC#Implementation

	// compute the block sized key
	uint8_t block_sized_key[hash_block_size];

	// keys longer than blockSize are shortened by hashing them
	if (key_length > hash_block_size) {
		// we can avoid additional SHA256_CTX instance by using the one in the ctx
		hash_alg->init(hash_ctx);
		hash_alg->update(hash_ctx, key, key_length);
		hash_alg->final(hash_ctx, block_sized_key);
		// SHA256 output is 32 bytes, pad with zeros on the right
		memset(&block_sized_key[32], 0, 32);
	} else {
		if (key_length > 0) {
			assert(key != NULL);
			memcpy(block_sized_key, key, key_length);
		}
		// keys shorter than blockSize are padded to blockSize by padding with zeros on the right
		if (key_length < hash_block_size) {
			memset(&block_sized_key[key_length], 0, hash_block_size - key_length);
		}
	}

	// compute the inner padded key and store it in the ctx->i_o_key_pad
	for (size_t i = 0; i < hash_block_size; i++) {
		i_o_key_pad[i] = block_sized_key[i] ^ 0x36u;
	}

	// start computing hash(i_key_pad || data...
	hash_alg->init(hash_ctx);
	hash_alg->update(hash_ctx, i_o_key_pad, hash_block_size);

	// compute the outer padded key and store it in the ctx->i_o_key_pad
	// so that it can be used by hmac_sha256_final
	for (size_t i = 0; i < hash_block_size; i++) {
		i_o_key_pad[i] = block_sized_key[i] ^ 0x5cu;
	}

}

void hmac_update(void *const ctx, const uint8_t *const data, const size_t data_length) {

	hmac_ctx_t *const hmac_ctx = ctx;
	const hash_alg_t *const hash_alg = hmac_ctx->hash_alg;
	void *hash_ctx = hmac_ctx->hash_ctx;

	hash_alg->update(hash_ctx, data, data_length);

}

void hmac_final(void *const ctx, uint8_t *const hmac) {

	hmac_ctx_t *const hmac_ctx = ctx;
	const hash_alg_t *const hash_alg = hmac_ctx->hash_alg;
	void *hash_ctx = hmac_ctx->hash_ctx;
	uint8_t *i_o_key_pad = (uint8_t *) (hmac_ctx + 1);

	// finish computing the inner_hash (use the output hmac buffer as a temporary storage)
	// inner_hash = hash(i_key_pad || data... )
	hash_alg->final(hash_ctx, hmac);

	// compute hmac = hash(o_key_pad || inner_hash)
	hash_alg->init(hash_ctx);
	hash_alg->update(hash_ctx, i_o_key_pad, hash_alg->block_size); // o_key_pad
	hash_alg->update(hash_ctx, hmac, hash_alg->output_size); // inner_hash
	hash_alg->final(hash_ctx, hmac); // hmac = hash(o_key_pad || inner_hash)

}
