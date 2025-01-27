#ifndef POKUSEW_GTEST_CUSTOM_ASSERTIONS_H
#define POKUSEW_GTEST_CUSTOM_ASSERTIONS_H

#include <gtest/gtest.h>

testing::AssertionResult SameBytes(
	const char *size_expr,
	const char *actual_expr,
	const char *expected_expr,
	size_t size,
	const uint8_t *actual,
	const uint8_t *expected
);

#define EXPECT_SAME_BYTES(actual, expected) EXPECT_PRED_FORMAT3(SameBytes, sizeof((actual)), (actual), (expected))

#endif // POKUSEW_GTEST_CUSTOM_ASSERTIONS_H
