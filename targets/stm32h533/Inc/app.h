#include <stdnoreturn.h>
#include "ctaphid.h"
#include "ctap.h"

extern ctaphid_state_t app_ctaphid;
extern ctap_state_t app_ctap;

noreturn void app_run(void);

void app_handle_incoming_hid_packet(const ctaphid_packet_t *packet);

void app_hid_report_send_queue_add(const ctaphid_packet_t *packet);

void app_hid_report_send_queue_send_one_if_possible(void);

bool app_hid_report_send_queue_is_empty(void);
