#include <ctap.h>

ctap_user_presence_result_t ctap_wait_for_user_presence(void) {
	return CTAP_UP_RESULT_ALLOW;
}
