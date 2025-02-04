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

constexpr uint8_t hex_char_to_int(const char &ch) {
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	}

	if (ch >= 'A' && ch <= 'F') {
		return ch - 'A' + 10;
	}

	if (ch >= 'a' && ch <= 'f') {
		return ch - 'a' + 10;
	}

	// invalid hex char
	return 0;
}

template<size_t N>
struct hex_str_to_bytes {
	std::array<char, N> str{};

	constexpr hex_str_to_bytes(const char *a) noexcept {
		for (size_t i = 0u; i < N; ++i) {
			str[i] = a[i];
		}
	}

	constexpr size_t get_num_bytes() const {
		size_t num_bytes = 0u;
		// one byte consists of two hex digits (0xAB)
		bool second_digit_needed = false;

		for (const auto &ch : str) {

			// ignore delimiters in the hex string, note that
			// (a) delimiters between the two hex digits of one byte are not allowed
			// (b) multiple consecutive delimiters are allowed
			//     as well as any number of leading/trailing delimiters
			if (!second_digit_needed && ch == ' ') {
				continue;
			}

			// this char must be a valid hex digit
			if (!(
				(ch >= '0' && ch <= '9')
				|| (ch >= 'A' && ch <= 'F')
				|| (ch >= 'a' && ch <= 'f')
			)) {
				return 0;
			}

			if (second_digit_needed) {
				num_bytes++;
				second_digit_needed = false;
				continue;
			}

			second_digit_needed = true;

		}

		// if second_digit_needed => incomplete last byte
		return !second_digit_needed ? num_bytes : 0;
	}

	constexpr auto is_valid() const {
		size_t num_bytes = 0u;
		// one byte consists of two hex digits (0xAB)
		bool second_digit_needed = false;

		for (const auto &ch : str) {

			// ignore delimiters in the hex string, note that
			// (a) delimiters between the two hex digits of one byte are not allowed
			// (b) multiple consecutive delimiters are allowed
			//     as well as any number of leading/trailing delimiters
			if (!second_digit_needed && ch == ' ') {
				continue;
			}

			// this char must be a valid hex digit
			if (!(
				(ch >= '0' && ch <= '9')
				|| (ch >= 'A' && ch <= 'F')
				|| (ch >= 'a' && ch <= 'f')
			)) {
				return false;
			}

			if (second_digit_needed) {
				num_bytes++;
				second_digit_needed = false;
				continue;
			}

			second_digit_needed = true;

		}

		// if second_digit_needed => incomplete last byte
		return !second_digit_needed;
	}

	constexpr auto size() const {
		return N;
	}
};

// only doing this part to decrease the value of N by 1 because of the terminating null char,
// otherwise would put this directly in constructor :(
// note:
//   This syntax is called a deduction guide template:
//   https://en.cppreference.com/w/cpp/language/class_template_argument_deduction#User-defined_deduction_guides
template<size_t N>
hex_str_to_bytes(const char (&)[N]) -> hex_str_to_bytes<N - 1>;

/**
 * Converts the given HEX string to an uint8_t array
 *
 * The HEX string can contains delimiters in the hex string, note that
 * (a) delimiters between the two hex digits of one byte are not allowed
 * (b) multiple consecutive delimiters are allowed
 *     as well as any number of leading/trailing delimiters
 *
 * For example:
 * "AB 55 CD" -> valid
 * "AB55 CD" -> valid
 * "AB55CD" -> valid
 * " AB55CD " -> valid
 * "55 8 8" -> INVALID (delimiters between the two hex digits of one byte are not allowed)
 *
 * When an invalid HEX string is given, for example like this:
 *
 *   constexpr auto data = hex::bytes<"AB 55CD ">();
 *
 * the compilation fails with a similar error message:
 *
 *   hex.hpp:176:2: error: static_assert failed due to requirement 'hex::hex_str_to_bytes<6>{{{53, 53, 32, 56, 32, 56}}}.is_valid()' "Invalid HEX string given!"
 *           static_assert(str.is_valid(), "Invalid HEX string given!");
 *           ^             ~~~~~~~~~~~~~~
 *
 * @tparam str a HEX string, optionally with spaces as delimiters
 * @return the byte array (uint8_t)
 */
template<hex_str_to_bytes str>
constexpr auto bytes() {

	static_assert(str.is_valid(), "Invalid HEX string given!");

	std::array<uint8_t, str.get_num_bytes()> result{};

	if (!str.is_valid()) {
		return result;
	}

	size_t result_i = 0u;
	// one byte consists of two hex digits (0xAB)
	bool second_digit_needed = false;

	for (size_t str_i = 0u; str_i < str.size(); ++str_i) {

		// ignore delimiters in the hex string
		// here, all other characters are already guaranteed to be valid hex string characters
		// (thanks to the check !str.is_valid() above), so no other checks are necessary
		if (str.str[str_i] == ' ') {
			continue;
		}

		if (second_digit_needed) {
			result[result_i] = 16 * hex_char_to_int(str.str[str_i - 1]) + hex_char_to_int(str.str[str_i]);
			result_i++;
			second_digit_needed = false;
			continue;
		}

		second_digit_needed = true;

	}

	return result;

}

}
