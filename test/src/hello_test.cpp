#include <gtest/gtest.h>
// https://stackoverflow.com/questions/47861534/why-does-google-test-sample-put-tests-in-an-anonymous-namespace
namespace {

// Demonstrate some basic assertions.
TEST(HelloTest, BasicAssertions) {

	int k = 0x7fffffff;
	// UndefinedBehaviorSanitizer: Signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
	k += 1;
	printf("a = %d\n", k);

	// Expect two strings not to be equal.
	EXPECT_STRNE("hello", "world");
	// Expect equality.
	EXPECT_EQ(7 * 6, 42);
}

} // namespace
