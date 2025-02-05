#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <uECC.h>
namespace {

constexpr auto key = hex::bytes<
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
>();
static_assert(key.size() == 32);

TEST(MicroEccTest, Basic) {

}

}
