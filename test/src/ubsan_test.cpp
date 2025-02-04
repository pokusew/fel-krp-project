#include <gtest/gtest.h>
namespace {

TEST(UbsanTest, SignedIntegerOverflow) {
	int k = 0x7fffffff;
	// UndefinedBehaviorSanitizer: Signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
	k += 1;
	printf("a = %d\n", k);
}

} // namespace
