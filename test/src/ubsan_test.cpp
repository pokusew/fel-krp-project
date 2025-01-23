#include <gtest/gtest.h>
// https://stackoverflow.com/questions/47861534/why-does-google-test-sample-put-tests-in-an-anonymous-namespace
namespace {

TEST(UbsanTest, SignedIntegerOverflow) {
	int k = 0x7fffffff;
	// UndefinedBehaviorSanitizer: Signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
	k += 1;
	printf("a = %d\n", k);
}

} // namespace
