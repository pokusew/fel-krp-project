#include <gtest/gtest.h>
#include <algorithm>
extern "C" {
#include <tusb.h>
}
namespace {

TEST(TusbFifoTest, Define) {
	TU_FIFO_DEF(test, 8, uint8_t[64], true);
	EXPECT_EQ(tu_fifo_depth(&test), 8);
	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 8);
}

TEST(TusbFifoTest, WriteFullThenReadFullThenWriteOne) {

	TU_FIFO_DEF(test, 3, int, false);

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

	int one = 1;
	int two = 2;
	int three = 3;
	int four = 4;

	ASSERT_EQ(tu_fifo_write(&test, &one), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 2);

	ASSERT_EQ(tu_fifo_write(&test, &two), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 1);

	ASSERT_EQ(tu_fifo_write(&test, &three), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), true);
	EXPECT_EQ(tu_fifo_remaining(&test), 0);

	ASSERT_EQ(tu_fifo_write(&test, &four), false);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), true);
	EXPECT_EQ(tu_fifo_remaining(&test), 0);

	int item;
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 1);
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 2);
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 3);

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

	ASSERT_EQ(tu_fifo_write(&test, &four), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 2);

	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 4);

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

}

TEST(TusbFifoTest, Overwrite) {

	TU_FIFO_DEF(test, 3, int, true);

	// fifo depth = 3
	// write 1 2 3 4 5
	// read      3 4 5

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

	int one = 1;
	int two = 2;
	int three = 3;
	int four = 4;
	int five = 5;

	ASSERT_EQ(tu_fifo_write(&test, &one), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 2);

	ASSERT_EQ(tu_fifo_write(&test, &two), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 1);

	ASSERT_EQ(tu_fifo_write(&test, &three), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), true);
	EXPECT_EQ(tu_fifo_remaining(&test), 0);

	ASSERT_EQ(tu_fifo_write(&test, &four), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), true);
	EXPECT_EQ(tu_fifo_remaining(&test), 0);

	ASSERT_EQ(tu_fifo_write(&test, &five), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), true);
	EXPECT_EQ(tu_fifo_remaining(&test), 0);

	int item;
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 3); // 1
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 4); // 2
	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 5);

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

	ASSERT_EQ(tu_fifo_write(&test, &four), true);
	EXPECT_EQ(tu_fifo_empty(&test), false);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 2);

	ASSERT_EQ(tu_fifo_read(&test, &item), true);
	EXPECT_EQ(item, 4);

	EXPECT_EQ(tu_fifo_empty(&test), true);
	EXPECT_EQ(tu_fifo_full(&test), false);
	EXPECT_EQ(tu_fifo_remaining(&test), 3);

}

} // namespace
