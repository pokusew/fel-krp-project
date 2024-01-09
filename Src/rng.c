#include "stm32f4xx_ll_rng.h"
#include "rng.h"
#include "log.h"
#include "utils.h"

void rng_get_bytes(uint8_t *dst, size_t sz) {
	uint8_t r[4];
	unsigned int i, j;
	for (i = 0; i < sz; i += 4) {
		while (!LL_RNG_IsActiveFlag_DRDY(RNG));
		*(uint32_t *) &r = LL_RNG_ReadRandData32(RNG);

		if (RNG->SR & 0x66) {
			error_log("Error RNG: RNG->SR=%02" PRIx32 nl, RNG->SR);
			Error_Handler();
		}

		for (j = 0; j < 4; j++) {
			if ((i + j) >= sz) {
				return;
			}
			dst[i + j] = r[j];
		}
	}
}
