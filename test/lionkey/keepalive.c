#include <ctap.h>

void ctap_send_keepalive_if_needed(ctap_keepalive_status_t current_status) {
	debug_log("ctap_send_keepalive_if_needed current_status=%d" wPRId8 nl, current_status);
	lion_unused(current_status);
}
