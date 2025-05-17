#ifndef LIONKEY_HASH_H
#define LIONKEY_HASH_H

#include <stdint.h>
#include <stddef.h>

typedef struct hash_alg {
	size_t ctx_size;
	size_t output_size;
	size_t block_size;
	void (*init)(void *ctx);
	void (*update)(void *ctx, const uint8_t *data, size_t data_length);
	void (*final)(void *ctx, uint8_t *hash);
} hash_alg_t;

#endif // LIONKEY_HASH_H
