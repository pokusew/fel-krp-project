#include "gtest_custom_assertions.h"
#include "fmt/format.h"
#include "fmt/ranges.h"

testing::AssertionResult SameBytes(
	const char *size_expr,
	const char *actual_expr,
	const char *expected_expr,
	size_t size,
	const uint8_t *actual,
	const uint8_t *expected
) {
	for (int i = 0; i < size; ++i) {
		if (actual[i] != expected[i]) {
			size_t field_width = std::max(strlen(actual_expr), strlen(expected_expr));
			return testing::AssertionFailure()
				<< fmt::format(
					"bytes differ when comparing {0} bytes ({1}):"
					"\n  {3:>{2}}: {4:02x}"
					"\n  {5:>{2}}: {6:02x}"
					"\n  {8:>{9}}  ^^ first diff at index = {7}",
					size, size_expr, field_width,
					actual_expr, fmt::join(actual, actual + size, ""),
					expected_expr, fmt::join(expected, expected + size, ""),
					i, "", field_width + (i * 2)
				);
		}
	}
	return testing::AssertionSuccess();
}
