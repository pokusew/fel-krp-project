#include <gtest/gtest.h>
#include <hex.hpp>

TEST(HexUtilsTest, ThreeBytesSeparated) {

	constexpr auto data = hex::bytes<"AB55CD">();

	static_assert(data.size() == 3);
	static_assert(data[0] == 0xAB);
	static_assert(data[1] == 0x55);
	static_assert(data[2] == 0xCD);

	ASSERT_EQ(data.size(), 3);
	EXPECT_EQ(data[0], 0xAB);
	EXPECT_EQ(data[1], 0x55);
	EXPECT_EQ(data[2], 0xCD);

}

TEST(HexUtilsTest, ThreeBytesSeparatedBySpace) {

	constexpr auto data = hex::bytes<"AB 55 CD">();

	static_assert(data.size() == 3);
	static_assert(data[0] == 0xAB);
	static_assert(data[1] == 0x55);
	static_assert(data[2] == 0xCD);

	ASSERT_EQ(data.size(), 3);
	EXPECT_EQ(data[0], 0xAB);
	EXPECT_EQ(data[1], 0x55);
	EXPECT_EQ(data[2], 0xCD);

}

TEST(HexUtilsTest, OneByteWithMixedCasing) {

	constexpr auto data = hex::bytes<"aF">();

	static_assert(data.size() == 1);
	static_assert(data[0] == 0xAF);

	ASSERT_EQ(data.size(), 1);
	ASSERT_EQ(data[0], 0xAF);

}

TEST(HexUtilsTest, ZeroBytes) {

	constexpr auto data = hex::bytes<"">();

	static_assert(data.size() == 0); // NOLINT(*-container-size-empty)

	ASSERT_EQ(data.size(), 0);

}
