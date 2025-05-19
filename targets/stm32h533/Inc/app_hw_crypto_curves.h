#ifndef LIONKEY_STM32H33_APP_HW_CRYPTO_CURVES_H
#define LIONKEY_STM32H33_APP_HW_CRYPTO_CURVES_H

#include <stdint.h>

typedef struct hw_crypto_ecc_curve {
	uint32_t prime_order_size; // number of bytes
	uint32_t modulus_size; // number of bytes
	uint32_t a_sign; // the sign of the curve coefficient A (0 for positive, 1 for negative)
	const uint8_t *abs_a; // absolute value of the curve coefficient A (array of modulus_size bytes)
	const uint8_t *b; // the curve coefficient B (array of modulus_size bytes)
	const uint8_t *p; // curve modulus value p (array of modulus_size bytes)
	const uint8_t *G; // curve base points xG and yG (array of 2 * modulus_size bytes)
	const uint8_t *xG; // curve base points xG and yG (array of 2 * modulus_size bytes)
	const uint8_t *yG; // curve base points xG and yG (array of 2 * modulus_size bytes)
	const uint8_t *n; // order of the curve (array of prime_order_size bytes)
} hw_crypto_ecc_curve_t;

extern const hw_crypto_ecc_curve_t hw_crypto_ecc_curve_secp256r1;

#endif // LIONKEY_STM32H33_APP_HW_CRYPTO_CURVES_H
