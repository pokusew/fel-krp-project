#ifndef POKUSEW_HMAC_H
#define POKUSEW_HMAC_H

#include <stdint.h>
#include <stddef.h>

#include "sha256.h"

typedef struct hmac_sha256_ctx {
	SHA256_CTX sha256_ctx;
	uint8_t i_o_key_pad[64];
} hmac_sha256_ctx_t;

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_length);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t length);
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *hmac);

#endif // POKUSEW_HMAC_H
