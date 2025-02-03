#include <gtest/gtest.h>
#include <hex.hpp>

TEST(HexUtilsTest, TwoBytesSeparatedBySpace) {

	constexpr auto data = hex::bytes<"55 8B">();

	static_assert(data[0] == 0x55);
	static_assert(data[1] == 0x8B);
	static_assert(data.size() == 2);

	ASSERT_EQ(data.size(), 2);
	EXPECT_EQ(data[0], 0x55);
	EXPECT_EQ(data[1], 0x8B);

}

TEST(HexUtilsTest, IncompleteTwoBytes) {

	constexpr auto data = hex::bytes<"55 8 8">();

	// TODO: fix bug
	static_assert(data[0] == 0x55);
	static_assert(data[1] == 0x49);
	static_assert(data[2] == 0x00);
	static_assert(data.size() == 3);

}
