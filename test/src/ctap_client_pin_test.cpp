#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <algorithm>
extern "C" {
#include <ctap.h>
#include <ctap_crypto_software.h>
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

constexpr auto create_set_pin_v1(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 64> &new_pin_enc,
	const std::array<uint8_t, 16> &pin_uv_auth_param
) {
	auto params = hex::bytes<
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
		"  01 01" // pinUvAuthProtocol = 1
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
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &params[86]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &params[105]);
	return params;
}

constexpr auto create_set_pin_v2(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 80> &new_pin_enc,
	const std::array<uint8_t, 32> &pin_uv_auth_param
) {
	auto params = hex::bytes<
		// {
		//     1: 2,
		//     2: 3,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     4: h'{pinUvAuthParam (0x04) (32 bytes)}',
		//     5: h'{newPinEnc (0x05) (80 bytes)}',
		// }
		"a5"
		"  01 02" // pinUvAuthProtocol = 2
		"  02 03"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  04 5820" // pinUvAuthParam (0x04) (32 bytes)
		"     cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		"  05 5850" // newPinEnc (0x05) (80 bytes)
		"     dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	>();
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &params[87]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &params[122]);
	return params;
}

constexpr auto create_change_pin_v1(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 16> &pin_hash_enc,
	const std::array<uint8_t, 64> &new_pin_enc,
	const std::array<uint8_t, 16> &pin_uv_auth_param
) {
	auto params = hex::bytes<
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
		"  01 01" // pinUvAuthProtocol = 1
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
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &params[86]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &params[105]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &params[171]);
	return params;
}

constexpr auto create_change_pin_v2(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 32> &pin_hash_enc,
	const std::array<uint8_t, 80> &new_pin_enc,
	const std::array<uint8_t, 32> &pin_uv_auth_param
) {
	auto params = hex::bytes<
		// {
		//     1: 2,
		//     2: 4,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     4: h'{pinUvAuthParam (0x04) (32 bytes)}',
		//     5: h'{newPinEnc (0x05) (80 bytes)}',
		//     6: h'{pinHashEnc (0x06) (32 bytes)}',
		// }
		"a6"
		"  01 02" // pinUvAuthProtocol = 2
		"  02 04"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  04 5820" // pinUvAuthParam (0x04) (32 bytes)
		"     cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		"  05 5850" // newPinEnc (0x05) (80 bytes)
		"     dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		"  06 5820" // pinHashEnc (0x06) (32 bytes)
		"     eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	>();
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_uv_auth_param.begin(), pin_uv_auth_param.size(), &params[87]);
	std::copy_n(new_pin_enc.begin(), new_pin_enc.size(), &params[122]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &params[205]);
	return params;
}

constexpr auto create_get_pin_token_v1(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 16> &pin_hash_enc
) {
	auto params = hex::bytes<
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
		"  01 01" // pinUvAuthProtocol = 1
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
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &params[86]);
	return params;
}

constexpr auto create_get_pin_token_v2(
	const std::array<uint8_t, 32> &x,
	const std::array<uint8_t, 32> &y,
	const std::array<uint8_t, 32> &pin_hash_enc
) {
	auto params = hex::bytes<
		// {
		//     1: 2,
		//     2: 5,
		//     3: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'{x}',
		//         -3: h'{y}',
		//     },
		//     6: h'{pinHashEnc (0x06) (32 bytes)}',
		// }
		"a4"
		"  01 02" // pinUvAuthProtocol = 2
		"  02 05"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"       22 5820" // y (32 bytes)
		"          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"  06 5820" // pinHashEnc (0x06) (32 bytes)
		"     eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	>();
	std::copy_n(x.begin(), x.size(), &params[17]);
	std::copy_n(y.begin(), y.size(), &params[52]);
	std::copy_n(pin_hash_enc.begin(), pin_hash_enc.size(), &params[87]);
	return params;
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
	uint8_t ctap_response_buffer[CTAP_RESPONSE_BUFFER_SIZE]{};
	ctap_software_crypto_context_t crypto_ctx{};
	const ctap_crypto_t crypto = CTAP_SOFTWARE_CRYPTO_CONST_INIT(&crypto_ctx);
	ctap_state_t ctap = CTAP_STATE_CONST_INIT(&crypto);
	ctap_response_t response{
		.data_max_size = sizeof(ctap_response_buffer),
		.data = ctap_response_buffer,
	};
	uint8_t status{};

	CtapClientPinTest() {
		crypto.init(&crypto, 0);
		ctap_init(&ctap);
	}

	template<size_t N>
	void test_ctap_client_pin(const std::array<uint8_t, N> &params) {
		static_assert(N >= 1, "params must have at least 1 byte (the CTAP command code)");
		status = ctap_request(
			&ctap,
			CTAP_CMD_CLIENT_PIN,
			N,
			params.data(),
			&response
		);
	}

};

TEST_F(CtapClientPinTest, InvalidSubcommandV1) {
	auto params = hex::bytes<
		// {1: 1, 2: 8}
		"a201010208"
	>();
	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_INVALID_SUBCOMMAND);
}

TEST_F(CtapClientPinTest, GetPinRetriesV1) {
	auto params = hex::bytes<
		// {1: 1, 2: 1}
		"a201010201"
	>();
	test_ctap_client_pin(params);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<"a2030804f4">();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, GetKeyAgreementV1) {
	auto params = hex::bytes<
		// {1: 1, 2: 2}
		"a201010202"
	>();
	test_ctap_client_pin(params);
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

TEST_F(CtapClientPinTest, SetPinV1To1234) {
	auto pin = hex::bytes<"31323334">();
	auto pin_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params = create_set_pin_v1(
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

	test_ctap_client_pin(params);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, SetPinV1OneCodePoint) {
	auto pin = hex::bytes<"f09f988c">();
	auto params = create_set_pin_v1(
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

	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_POLICY_VIOLATION);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, PIN_TOTAL_ATTEMPTS);
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, PIN_PER_BOOT_ATTEMPTS);
}

TEST_F(CtapClientPinTest, SetPinV1Emoji) {
	auto pin = hex::bytes<"f09f988cf09f918df09f8fbb34">();
	auto pin_hash = hex::bytes<
		"b9157af8f2947a41039aaa274f1568a691b7494531d93282a73ff993d7b99494"
	>();
	auto params = create_set_pin_v1(
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

	test_ctap_client_pin(params);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, ChangePinV1From1234ToABCD) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params_set_pin_1234 = create_set_pin_v1(
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
	auto params_change_pin_from_1234_to_ABCD = create_change_pin_v1(
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

	test_ctap_client_pin(params_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_client_pin(params_change_pin_from_1234_to_ABCD);
	EXPECT_SUCCESS_EMPTY_RESPONSE();
}

TEST_F(CtapClientPinTest, GetPinTokenV1) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params_set_pin_1234 = create_set_pin_v1(
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
	auto params_get_pin_token = create_get_pin_token_v1(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"d5709a66faf48f8da0adde8556d3ce5f"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_client_pin(params_get_pin_token);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<
		"a1"
		"  02 5820"
		"     843101d90842f76114967a04b815dd5a5f216a857c7935d1601014f1ddb3f45b"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, InvalidSubcommandV2) {
	auto params = hex::bytes<
		// {1: 2, 2: 8}
		"a201020208"
	>();
	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_INVALID_SUBCOMMAND);
}

TEST_F(CtapClientPinTest, GetPinRetriesV2) {
	auto params = hex::bytes<
		// {1: 2, 2: 1}
		"a201020201"
	>();
	test_ctap_client_pin(params);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<"a2030804f4">();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, GetKeyAgreementV2) {
	auto params = hex::bytes<
		// {1: 2, 2: 2}
		"a201020202"
	>();
	test_ctap_client_pin(params);
	EXPECT_EQ(status, CTAP2_OK);
	auto expected_response = hex::bytes<
		// {
		//     1: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'ada80bf2155208a482007a76b77100f37a0b78a1f5aaf7a20193fa4630bb8490',
		//         -3: h'f0143340ed13ba4e5546728599a02ce3f170b40eb9dfd8d23454fd98192feee3',
		//     },
		// }
		"a1"
		"01"
		"a5"
		"01 02"
		"03 38 18"
		"20 01"
		"21 58 20"
		"ada80bf2155208a482007a76b77100f37a0b78a1f5aaf7a20193fa4630bb8490"
		"22 58 20"
		"f0143340ed13ba4e5546728599a02ce3f170b40eb9dfd8d23454fd98192feee3"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

TEST_F(CtapClientPinTest, SetPinV2To1234) {
	auto pin = hex::bytes<"31323334">();
	auto pin_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params = create_set_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"4626cf7346caca5b40799ca5cbf78b05cf9f54851de519db01cb5c473b506a19"
			"9c0cdf66e8c035913659921be351c7f316fabb5ade601fc2d1c9d287df736c88"
			"d848006a55fb1185e09a847323d8e1a1"
		>(),
		hex::bytes<
			"4bb742287a11f80748a26f39242cef6d2cf9f5ba205968c0a6f1afb26be7c071"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	dump_hex(params.data(), params.size());
	test_ctap_client_pin(params);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, SetPinV2OneCodePoint) {
	auto pin = hex::bytes<"f09f988c">();
	auto params = create_set_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"bca644b0eb9fe7592de8a9c920baa72192a6b7b9760a5c83c01c461f29bb372f"
			"7630c545b0b34e8a7b49ef56e3f2fece2868b9d64dcf933fd37b408ac9e70fe6"
			"b991f49980e183f86f7c62cbdbfa2118"
		>(),
		hex::bytes<
			"203844bca95258e5f93c037a8e2557459eb42a9f6a49fa0727f8b27d647b7d0d"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_POLICY_VIOLATION);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, PIN_TOTAL_ATTEMPTS);
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, PIN_PER_BOOT_ATTEMPTS);
}

TEST_F(CtapClientPinTest, SetPinV2Emoji) {
	auto pin = hex::bytes<"f09f988cf09f918df09f8fbb34">();
	auto pin_hash = hex::bytes<
		"b9157af8f2947a41039aaa274f1568a691b7494531d93282a73ff993d7b99494"
	>();
	auto params = create_set_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"5a422d461b334320a34bc67dc82243ac7da263b2f77dd738a77ab9e01226140a"
			"0f453fa7a551a0b51616401528e70ad52af2e9185efc59129e5d08416ada0e9f"
			"30c7597d0420febc7b0b77a74df71da6"
		>(),
		hex::bytes<
			"3a312652abe1d87438a015db15ae3ac4021556c673c016fde36566b62e5b222b"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, ChangePinV2From1234ToABCD) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params_set_pin_1234 = create_set_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"4626cf7346caca5b40799ca5cbf78b05cf9f54851de519db01cb5c473b506a19"
			"9c0cdf66e8c035913659921be351c7f316fabb5ade601fc2d1c9d287df736c88"
			"d848006a55fb1185e09a847323d8e1a1"
		>(),
		hex::bytes<
			"4bb742287a11f80748a26f39242cef6d2cf9f5ba205968c0a6f1afb26be7c071"
		>()
	);
	auto pin_ABCD = hex::bytes<"41424344">();
	auto pin_ABCD_hash = hex::bytes<
		"e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677"
	>();
	auto params_change_pin_from_1234_to_ABCD = create_change_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"cc1334272aff0595ccb47418d32a0554104419dfa8a72580cb61fe5f69250908"
		>(),
		hex::bytes<
			"059d39f545995d01117192bd078d9a320dfe7890442928b6157a1a3528b75de8"
			"fa0a20b4a144fdeac4c21d3defb8e237848727ca2de73a0283af4a8dc31edcd6"
			"f68c8cd1e7ec408a0bac106fe1b8e2fb"
		>(),
		hex::bytes<
			"f8dba90ec042ec61d02bd33fad7fb37598993a1487f203fad89c3e1ebd0c13fc"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_client_pin(params_change_pin_from_1234_to_ABCD);
	EXPECT_SUCCESS_EMPTY_RESPONSE();
}

TEST_F(CtapClientPinTest, GetPinTokenV2) {
	auto pin_1234 = hex::bytes<"31323334">();
	auto pin_1234_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	auto params_set_pin_1234 = create_set_pin_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"4626cf7346caca5b40799ca5cbf78b05cf9f54851de519db01cb5c473b506a19"
			"9c0cdf66e8c035913659921be351c7f316fabb5ade601fc2d1c9d287df736c88"
			"d848006a55fb1185e09a847323d8e1a1"
		>(),
		hex::bytes<
			"4bb742287a11f80748a26f39242cef6d2cf9f5ba205968c0a6f1afb26be7c071"
		>()
	);
	auto params_get_pin_token = create_get_pin_token_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"cc1334272aff0595ccb47418d32a0554104419dfa8a72580cb61fe5f69250908"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params_set_pin_1234);
	EXPECT_SUCCESS_EMPTY_RESPONSE();

	EXPECT_PIN_SET_SUCCESSFULLY();
	EXPECT_EQ(ctap.persistent.pin_code_point_length, 4);
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_1234_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_1234_hash.data());

	test_ctap_client_pin(params_get_pin_token);
	EXPECT_EQ(status, CTAP2_OK);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<
		"a1"
		"  02 5830"
		"     517874b740cbdca41920aa0ed61c14d28ab4488f1b13fbfc77242053b93ddc406eab39f9bd2ac29570f9268810fea592"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

} // namespace
