#include <ctap.h>

ctap_user_presence_result_t ctap_wait_for_user_presence(void) {
	debug_log("returning CTAP_UP_RESULT_ALLOW from ctap_wait_for_user_presence" nl);
	return CTAP_UP_RESULT_ALLOW;
}
