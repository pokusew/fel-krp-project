#ifndef LIONKEY_STM32H533_APP_TEST_H
#define LIONKEY_STM32H533_APP_TEST_H

void app_debug_task(void);

void app_test_flash(void);

void app_test_flash_high_cycling(void);

void app_test_rng_tinymt(void);

void app_test_rng_hw(void);

void app_test_ecc_sign(void);

void app_test_ecc_compute_public_key(void);

void app_test_ecc_shared_secret(void);

void app_test_aes(void);

void app_test_hash_zero(void);

void app_test_hash_big(void);

void app_test_hash_big_two_parts(void);

#endif // LIONKEY_STM32H533_APP_TEST_H
