#ifndef LIONKEY_HMAC_H
#define LIONKEY_HMAC_H

#include <stdint.h>
#include <stddef.h>

#include "sha256.h"

typedef struct hmac_sha256_ctx {
	sha256_ctx_t sha256_ctx;
	uint8_t i_o_key_pad[LIONKEY_SHA256_BLOCK_SIZE];
} hmac_sha256_ctx_t;

/**
 * Initializes HMAC computation
 *
 * See RFC 2104: HMAC: Keyed-Hashing for Message Authentication,
 * https://datatracker.ietf.org/doc/html/rfc2104, or see https://en.wikipedia.org/wiki/HMAC.
 *
 * @param [out] ctx the HMAC context, will be initialized by this function
 * @param [in] key the key
 * @param [in] key_length the key length in bytes (arbitrary length allowed)
 */
void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_length);

/**
 * Updates the HMAC computation by processing the given data
 *
 * @param [in,out] ctx the HMAC context
 * @param [in] data the data
 * @param [in] data_length the data length in bytes
 */
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t data_length);

/**
 * Finalizes the HMAC computation and returns the computed hmac digest
 *
 * @param [in,out] ctx the HMAC context
 * @param [out] hmac the computed hmac digest, must be a buffer of LIONKEY_SHA256_OUTPUT_SIZE bytes
 */
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *hmac);

#endif // LIONKEY_HMAC_H
