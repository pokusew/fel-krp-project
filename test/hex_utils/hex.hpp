//
// Compile-time (build-time) byte arrays from hex strings
//
// credits (original version): https://www.unknowncheats.me/forum/3135334-post10.html
//
// USAGE:
//
//   constexpr auto data = hex::bytes<"55 8B">();
//
// 	 static_assert(data[0] == 0x55);
// 	 static_assert(data[1] == 0x8B);
// 	 static_assert(data.size() == 2);
//
//
// Note: The used syntax requires at least C++20.
//
//   In CMake, it is possible to set the C++ standard per target via
//   target compile feature requirements (https://cmake.org/cmake/help/latest/manual/cmake-compile-features.7.html#requiring-language-standards):
//     target_compile_features(hex_utils INTERFACE cxx_std_20)
//   or directly via the CXX_STANDARD and CXX_STANDARD_REQUIRED properties (https://cmake.org/cmake/help/latest/prop_tgt/CXX_STANDARD.html)
//     set_target_properties(<target> PROPERTIES CXX_STANDARD 20)
//     set_target_properties(<target> PROPERTIES CXX_STANDARD_REQUIRED true)

#include <array>
#include <cstdint>

namespace hex {

constexpr uint8_t char_to_int(const char &ch) {
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	}

	if (ch >= 'A' && ch <= 'F') {
		return ch - 'A' + 10;
	}

	return ch - 'a' + 10;
}

template<size_t N>
struct str_to_ba {
	std::array<char, N> str{};

	constexpr str_to_ba(const char *a)

	noexcept {
		for (size_t i = 0u; i < N; ++i) {
			str[i] = a[i];
		}
	}

	[[nodiscard]] constexpr size_t get_skip_count() const {
		size_t skips = 0u;
		bool skip_next_char = false;

		for (size_t i = 0u; i < N; ++i) {

			// delimiter
			if (str[i] == ' ') {
				++skips;
				continue;
			}

			if (!skip_next_char) {
				// hit char pair
				if (i + 1 < N && str[i + 1] != ' ') {
					skip_next_char = true;
				}
				continue;
			}

			// do only 1 skip for char pair
			++skips;
			skip_next_char = false;

		}

		return skips;
	}

	constexpr auto size() const {
		return N;
	}
};

// only doing this part to decrease size of N by 1 because of the terminating null char,
// otherwise would put this directly in constructor :(
template<size_t N>
str_to_ba(const char(&)[N])->str_to_ba<N - 1>;

/**
 *
 * @tparam str HEX string, spaces are allowed
 * @return
 */
template<str_to_ba str>
constexpr auto bytes() {

	std::array<uint8_t, str.size() - str.get_skip_count()> result{};

	size_t result_i = 0u;
	bool skip_next_char = false;

	for (size_t str_i = 0u; str_i < str.size(); ++str_i) {

		// delimiting wildcard
		if (str.str[str_i] == ' ') {
			continue;
		}

		// already consumed character
		if (skip_next_char) {
			skip_next_char = false;
			continue;
		}

		// one byte is two hex digits (characters) 0xAB
		if (str_i + 1 < str.size()) {
			// set and increase
			// TODO: fix edge case bug hex::bytes<"55 8 8">()
			result[result_i++] = 16 * char_to_int(str.str[str_i]) + char_to_int(str.str[str_i + 1]);
			skip_next_char = true;
		}
	}

	return result;
}

}
