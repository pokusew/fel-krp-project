#include <stdnoreturn.h>
#include "ctaphid.h"
#include "ctap.h"

extern ctaphid_state_t app_ctaphid;
extern ctap_state_t app_ctap;

noreturn void app_run(void);

void app_handle_incoming_hid_packet(const ctaphid_packet_t *packet);

void send_or_queue_ctaphid_packet(const ctaphid_packet_t *packet);
