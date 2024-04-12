#include "time.h"

millis_t timestamp_diff(millis_t start) {
	millis_t now = millis();
	return now - start;
}
