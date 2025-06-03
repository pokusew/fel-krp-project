#ifndef LIONKEY_STM32H533_APP_H
#define LIONKEY_STM32H533_APP_H

#include <stdnoreturn.h>
#include "ctaphid.h"
#include "ctap.h"

extern const ctap_storage_t app_storage;

extern const ctap_crypto_t app_sw_crypto;
extern const ctap_crypto_t app_hw_crypto;

extern ctaphid_state_t app_ctaphid;
extern ctap_state_t app_ctap;

noreturn void app_run(void);

void app_hid_task(void);

void app_handle_incoming_hid_packet(const ctaphid_packet_t *packet);

void app_hid_report_send_queue_add(const ctaphid_packet_t *packet, bool fail_if_full);

void app_hid_report_send_queue_send_one_if_possible(void);

bool app_hid_report_send_queue_is_empty(void);

#endif // LIONKEY_STM32H533_APP_H
