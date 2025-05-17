#ifndef LIONKEY_HMAC_H
#define LIONKEY_HMAC_H

#include <stdint.h>
#include <stddef.h>
#include <hash.h>

size_t hmac_get_context_size(const hash_alg_t *hash_alg);

/**
 * Initializes HMAC computation
 *
 * See RFC 2104: HMAC: Keyed-Hashing for Message Authentication,
 * https://datatracker.ietf.org/doc/html/rfc2104, or see https://en.wikipedia.org/wiki/HMAC.
 *
 * @param [out] ctx the HMAC context, will be initialized by this function
 * @param [in] hash_alg the hashing algorithm to use
 * @param [in] key the key
 * @param [in] key_length the key length in bytes (arbitrary length allowed)
 */
void hmac_init(void *ctx, const hash_alg_t *hash_alg, const uint8_t *key, size_t key_length);

/**
 * Updates the HMAC computation by processing the given data
 *
 * @param [in,out] ctx the HMAC context
 * @param [in] data the data
 * @param [in] data_length the data length in bytes
 */
void hmac_update(void *ctx, const uint8_t *data, size_t data_length);

/**
 * Finalizes the HMAC computation and returns the computed hmac digest
 *
 * @param [in,out] ctx the HMAC context
 * @param [out] hmac the computed hmac digest, must be a buffer of LIONKEY_SHA256_OUTPUT_SIZE bytes
 */
void hmac_final(void *ctx, uint8_t *hmac);

#endif // LIONKEY_HMAC_H
