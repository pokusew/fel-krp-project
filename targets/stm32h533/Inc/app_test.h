#ifndef LIONKEY_STM32H33_APP_TEST_H
#define LIONKEY_STM32H33_APP_TEST_H

void app_test_rng_tinymt(void);

void app_test_rng_hw(void);

void app_test_ecc_sign(void);

void app_test_ecc_compute_public_key(void);

void app_test_ecc_shared_secret(void);

void app_test_aes(void);

void app_test_hash_zero(void);

void app_test_hash_big(void);

void app_test_hash_big_two_parts(void);

#endif // LIONKEY_STM32H33_APP_TEST_H
