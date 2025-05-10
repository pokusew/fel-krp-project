/**
 * SHA-256 implementation
 * Original author: Brad Conte (brad AT bradconte.com)
 * Original source: https://github.com/B-Con/crypto-algorithms/blob/master/sha256.h
 * Modified by Martin Endler for the LionKey project.
 */

#ifndef LIONKEY_SHA256_H
#define LIONKEY_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define LIONKEY_SHA256_OUTPUT_SIZE 32 // SHA-256 outputs a 32-byte digest
#define LIONKEY_SHA256_BLOCK_SIZE 64 // SHA-256 uses a 64-byte block

typedef struct sha256_ctx {
	uint8_t data[LIONKEY_SHA256_BLOCK_SIZE];
	uint32_t data_length;
	uint64_t bit_length;
	uint32_t state[8];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t data_length);
void sha256_final(sha256_ctx_t *ctx, uint8_t *hash);

#endif // LIONKEY_SHA256_H
