#include <random>
#include "utils.h"

namespace {

// https://stackoverflow.com/questions/922358/consistent-pseudo-random-numbers-across-platforms
// https://stackoverflow.com/questions/34903356/c11-random-number-distributions-are-not-consistent-across-platforms-what-al
// -> Based on those discussions, the C++11 mt19937 should deliver consistent results across all platforms.
//    Note that if for some reason it stopped working, we would notice in our CI.
// Here we intentionally use a constant fixed seed to generate
// a predictable sequence for consistent deterministic unit tests.
std::mt19937 rand(0); // NOLINT(*-msc51-cpp)

extern "C" void ctap_rng_reset(uint32_t seed) {
	rand.seed(seed);
}

extern "C" int ctap_generate_rng(uint8_t *buffer, size_t length) {
	debug_log("ctap_generate_rng: %zu bytes to %p" nl, length, buffer);
	for (size_t i = 0; i < length; ++i) {
		// TODO: Consider using the full uint32_t output of std::mt19937 rand(),
		//       i.e., use one rand() output to set (up to) four bytes of the buffer at once.
		buffer[i] = (uint8_t) rand();
	}
	return 1;
}

}
