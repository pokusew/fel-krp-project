#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
#include <utils.h>
}
namespace {

constexpr auto test_platform_private_key = hex::bytes<
	"b6a7164827e98933906aa13b90dd8bf6a15989a3419d90ecc1cde95a80aefb6c"
>();
constexpr auto test_platform_public_key_x = hex::bytes<
	"bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
>();
constexpr auto test_platform_public_key_y = hex::bytes<
	"d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
>();

constexpr auto create_set_pin(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 64> &new_pin_enc,
	const std::array<uint8_t, 16> &pin_uv_auth_param
) {
	auto request = hex::bytes<
		"06" // authenticatorClientPIN
		// {
		//     1: 1,
		//     2: 3,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     4: h'{pinUvAuthParam (0x04) (16 bytes)}',
		//     5: h'{newPinEnc (0x05) (64 bytes)}',
		// }
		"a5"
		"  01 01"
		"  02 03"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  04 50" // pinUvAuthParam (0x04) (16 bytes)
		"     cccccccccccccccccccccccccccccccc"
		"  05 5840" // newPinEnc (0x05) (64 bytes)
		"     dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	>();
	std::copy_n(x.begin(), x.size(), &request[18]);
	std::copy_n(y.begin(), y.size(), &request[53]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &request[87]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &request[106]);
	return request;
}

constexpr auto create_change_pin(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 16> &pin_hash_enc,
	const std::array<uint8_t, 64> &new_pin_enc,
	const std::array<uint8_t, 16> &pin_uv_auth_param
) {
	auto request = hex::bytes<
		"06" // authenticatorClientPIN
		// {
		//     1: 1,
		//     2: 4,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     4: h'{pinUvAuthParam (0x04) (16 bytes)}',
		//     5: h'{newPinEnc (0x05) (64 bytes)}',
		//     6: h'{pinHashEnc (0x06) (16 bytes)}',
		// }
		"a6"
		"  01 01"
		"  02 04"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  04 50" // pinUvAuthParam (0x04) (16 bytes)
		"     cccccccccccccccccccccccccccccccc"
		"  05 5840" // newPinEnc (0x05) (64 bytes)
		"     dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		"  06 50" // pinHashEnc (0x06) (16 bytes)
		"     eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	>();
	std::copy_n(x.begin(), x.size(), &request[18]);
	std::copy_n(y.begin(), y.size(), &request[53]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &request[87]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &request[106]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &request[106]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &request[172]);
	return request;
}

constexpr auto create_get_pin_token(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 16> &pin_hash_enc
) {
	auto request = hex::bytes<
		"06" // authenticatorClientPIN
		// {
		//     1: 1,
		//     2: 5,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     6: h'{pinHashEnc (0x06) (16 bytes)}',
		// }
		"a4"
		"  01 01"
		"  02 05"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  06 50" // pinHashEnc (0x06) (16 bytes)
		"     eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	>();
	std::copy_n(x.begin(), x.size(), &request[18]);
	std::copy_n(y.begin(), y.size(), &request[53]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &request[87]);
	return request;
}

#define EXPECT_ERROR_RESPONSE(expected_status) \
	EXPECT_EQ(status, expected_status); \
	EXPECT_EQ(response.length, 0)

#define EXPECT_SUCCESS_EMPTY_RESPONSE() \
	EXPECT_EQ(status, CTAP2_OK); \
	EXPECT_EQ(response.length, 0)

#define EXPECT_PIN_SET_SUCCESSFULLY() \
	EXPECT_EQ(ctap.persistent.is_pin_set, true); \
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, PIN_TOTAL_ATTEMPTS); \
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, PIN_PER_BOOT_ATTEMPTS)


class CtapClientPinTest : public testing::Test {
protected:
	ctap_state_t ctap{};
	ctap_response_t &response = ctap.response;
	uint8_t status{};

	CtapClientPinTest() {

		// reset the consistent pseudo random number generator between tests
		// This is needed because the generator is global and multiple test cases
		// run sequentially (in one executable), each affecting the generator state.
		// We plan to improve the API to remove the global state and switch to an instance-based (context) API.
		ctap_rng_reset(0);

		ctap_init(&ctap);

	}

	template<size_t N>
	void test_ctap_request(const std::array<uint8_t, N> &request) {
		static_assert(N >= 1, "request must have at least 1 byte (the CTAP command code)");
		status = ctap_request(
			&ctap,
			request.data()[0],
			N - 1, &request.data()[1]
		);
	}

};

TEST_F(CtapClientPinTest, InvalidSubcommand) {
	auto request = hex::bytes<
		"06" // CTAP_CMD_CLIENT_PIN
		// {1: 1, 2: 9}
		"a2" // map(2)
		"01" //   unsigned(1)
		"01" //   unsigned(1)
		"02" //   unsigned(2)
		"08" //   unsigned(9)
	>();
	test_ctap_request(request);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_INVALID_SUBCOMMAND);
}

TEST_F(CtapClientPinTest, GetPinRetries) {
	// 0x06 {1: 1, 2: 1}
	auto request = hex::bytes<"06 a2 01 01 02 01">();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<"a2 03 08 04 f4">();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, GetKeyAgreement) {
	// 0x06 {1: 1, 2: 2}
	auto request = hex::bytes<"06 a2 01 01 02 02">();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	auto expected_response = hex::bytes<
		// {
		//     1: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'2fec0a433af4ff216b7996d7304614be3ff2238e9d4b0b63337ea0fcac6967d0',
		//         -3: h'6d78c07b4cabd8b82f03870a74f23f5a2a655d17703df812dabab1a5f273acfa',
		//     },
		// }
		"a1"
		"01"
		"a5"
		"01 02"
		"03 38 18"
		"20 01"
		"21 58 20"
		"2fec0a433af4ff216b7996d7304614be3ff2238e9d4b0b63337ea0fcac6967d0"
		"22 58 20"
		"6d78c07b4cabd8b82f03870a74f23f5a2a655d17703df812dabab1a5f273acfa"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, SetPin1234) {
	auto pin = hex::bytes<"31323334">();
	auto pin_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto request = create_set_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"6fcb98a4f15a272ad14c2a04db36c744b712cf3159e1d008cdcf97808b64996f"
			"d4d8693bc4585281f1c165085c44bfe8e9b79db3dd83c89553514924ee6bf27a"
		>(),
		hex::bytes<
			"dd2b83def33954d24a7487621cf30c1e"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_request(request);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, SetPinOneCodePoint) {
	auto pin = hex::bytes<"f09f988c">();
	auto request = create_set_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"9e4be6a1088b1d160011490dcd2ea2d072308d7667b2cebda21579ac60803625"
			"bbba940068e8b364000cd609d4b6ebefd3e770c2153bbd46f29530087b911b7a"
		>(),
		hex::bytes<
			"35cca44689668d8a617d24ac69012676"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_request(request);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_POLICY_VIOLATION);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, PIN_TOTAL_ATTEMPTS);
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, PIN_PER_BOOT_ATTEMPTS);
}

TEST_F(CtapClientPinTest, SetPinEmoji) {
	auto pin = hex::bytes<"f09f988cf09f918df09f8fbb34">();
	auto pin_hash = hex::bytes<
		"b9157af8f2947a41039aaa274f1568a691b7494531d93282a73ff993d7b99494"
	>();
	auto request = create_set_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"e6072ff51fb7bbd3ea0246081d3ca565764d7209b1d388351ed55471b62b926b"
			"0bb6ec51090b6d883d4c85ae8696fedf8049007841d49e44ae7bc4c2f6efa7a6"
		>(),
		hex::bytes<
			"7f3b1214527119edc0d16b75917b94a6"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_request(request);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, ChangePinFrom1234ToABCD) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto request_set_pin_1234 = create_set_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"6fcb98a4f15a272ad14c2a04db36c744b712cf3159e1d008cdcf97808b64996f"
			"d4d8693bc4585281f1c165085c44bfe8e9b79db3dd83c89553514924ee6bf27a"
		>(),
		hex::bytes<
			"dd2b83def33954d24a7487621cf30c1e"
		>()
	);
	auto pin_ABCD = hex::bytes<"41424344">();
	auto pin_ABCD_hash = hex::bytes<
		"e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677"
	>();
	auto request_change_pin_from_1234_to_ABCD = create_change_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"d5709a66faf48f8da0adde8556d3ce5f"
		>(),
		hex::bytes<
			"6a2e11cb04bac6dd09a8131f95f17d4aa75c9e64feca4f32ba0ae5f855bf30d2"
			"c4348372342718c4344ad1500ec8e373808c045ed67bdd445cd40c10003c9ee1"
		>(),
		hex::bytes<
			"87c6d23b57eb602a9db5ef5e9dfd2a9d"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_request(request_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_request(request_change_pin_from_1234_to_ABCD);
	EXPECT_SUCCESS_EMPTY_RESPONSE();
}

TEST_F(CtapClientPinTest, GetPinToken) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto request_set_pin_1234 = create_set_pin(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"6fcb98a4f15a272ad14c2a04db36c744b712cf3159e1d008cdcf97808b64996f"
			"d4d8693bc4585281f1c165085c44bfe8e9b79db3dd83c89553514924ee6bf27a"
		>(),
		hex::bytes<
			"dd2b83def33954d24a7487621cf30c1e"
		>()
	);
	auto request_get_pin_token = create_get_pin_token(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"d5709a66faf48f8da0adde8556d3ce5f"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_request(request_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_request(request_get_pin_token);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<
		"a1"
		"  02 5820"
		"     d48de1f5391b32d493be84af08eff0f31ae18ae477b98c7a695415ff9c59dad9"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

} // namespace
