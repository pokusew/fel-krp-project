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
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, CTAP_PIN_TOTAL_ATTEMPTS); \
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, CTAP_PIN_PER_BOOT_ATTEMPTS)


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
		//         -2: h'78b110adb2f168a39a5fa453c71e86a64ed95b909b87d9ccb0e635ae3ed1517b',
		//         -3: h'1d1b7cf464db2b5df507e4848873a35ea18882336e0e7fe6524e18b573215fc3',
		//     },
		// }
		"a1"
		"01"
		"a5"
		"01 02"
		"03 38 18"
		"20 01"
		"21 58 20"
		"78b110adb2f168a39a5fa453c71e86a64ed95b909b87d9ccb0e635ae3ed1517b"
		"22 58 20"
		"1d1b7cf464db2b5df507e4848873a35ea18882336e0e7fe6524e18b573215fc3"
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
			"a8adf691fc0931227817b435a7bcf1f192b4198799416c1cfff993e46182aaca"
			"dc4b21517bcbe58cecbb606a8df1cedf40cb7c79c86bc8f3142502175643450f"
		>(),
		hex::bytes<
			"ca787d2f472d341660b372a629551dd2"
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
			"75383a449341501c2ed265df58b621313b3c2bb27214ed29a4230134e897bc69"
			"d7279faeb4523e64ace8e26e3dfac44b7e8006a8440fcf2ca9c021dea9edb2eb"
		>(),
		hex::bytes<
			"ece228e289a402804c3b2b32a463d0fc"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_POLICY_VIOLATION);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, CTAP_PIN_TOTAL_ATTEMPTS);
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, CTAP_PIN_PER_BOOT_ATTEMPTS);
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
			"8dac262c8ba2e95da56fce3b37ff9b62b9894681efe41b3a1ac292b15568fdff"
			"61b0f3e94212af7e636d042c2c249c35a0a68e812730329e6c2f84f9c77ceb91"
		>(),
		hex::bytes<
			"f8266ece1557b82fa8154f4d34b0478a"
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
			"a8adf691fc0931227817b435a7bcf1f192b4198799416c1cfff993e46182aaca"
			"dc4b21517bcbe58cecbb606a8df1cedf40cb7c79c86bc8f3142502175643450f"
		>(),
		hex::bytes<
			"ca787d2f472d341660b372a629551dd2"
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
			"f8bb2954bb38ded5e78cc7de04600f74"
		>(),
		hex::bytes<
			"081b4773243c506f9abaeb546a615e81b78b8a118f3424bc1bec3e6a31353809"
			"d870b95420474fe2150fb81ddd5d4090feea180f1f13c7973ed75349e79fbf1a"
		>(),
		hex::bytes<
			"6d0321cafeacb682a9ea0e1089e70c3e"
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
			"a8adf691fc0931227817b435a7bcf1f192b4198799416c1cfff993e46182aaca"
			"dc4b21517bcbe58cecbb606a8df1cedf40cb7c79c86bc8f3142502175643450f"
		>(),
		hex::bytes<
			"ca787d2f472d341660b372a629551dd2"
		>()
	);
	auto params_get_pin_token = create_get_pin_token_v1(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"f8bb2954bb38ded5e78cc7de04600f74"
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
		"     cffbc58ed2c03954d25bb93d3d612ad58af8825444fbe69af8284e306bf6afcb"
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
		//         -2: h'f09d2dcc4d511c5a3fb5b5810301e34aae76a1d372e2595e6f2843258525d24f',
		//         -3: h'dbb6ce2d43ccded46901977184a23bc66a6c5adf27c522c389e71c09e4c05281',
		//     },
		// }
		"a1"
		"01"
		"a5"
		"01 02"
		"03 38 18"
		"20 01"
		"21 58 20"
		"f09d2dcc4d511c5a3fb5b5810301e34aae76a1d372e2595e6f2843258525d24f"
		"22 58 20"
		"dbb6ce2d43ccded46901977184a23bc66a6c5adf27c522c389e71c09e4c05281"
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
			"40fda15406e29bef471e92be92a84e6d7bf445644b8c199060334e628c04c1f9"
			"a44df3d52e2c448fe46825ae833ae3a8dc60d30db85b273bb63fb79a370c9f39"
			"7803a1079a6f305a75f5601b06e74f32"
		>(),
		hex::bytes<
			"bc8852f6c9b62e9b9d01f648184eea19b73847c0ed4d68cbfe47b3196b475a40"
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
			"a5fa76974a1744f2e03cbfd1b2f01ac58dbac559abc667c7605f1b0771818c9e"
			"67a1cf4c29dbc4d24115e009a1a938eb1fc3a65007229920fdce4ecc148c19d35"
			"caa90c4dfc5da465a6ccb0bf9d06447"
		>(),
		hex::bytes<
			"6fb5638f9e3b2ffa24d9b2df69ecf6732af8395b644121989be092b08b6f485f"
		>()
	);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);

	test_ctap_client_pin(params);
	EXPECT_ERROR_RESPONSE(CTAP2_ERR_PIN_POLICY_VIOLATION);

	EXPECT_EQ(ctap.persistent.is_pin_set, false);
	EXPECT_EQ(ctap.persistent.pin_total_remaining_attempts, CTAP_PIN_TOTAL_ATTEMPTS);
	EXPECT_EQ(ctap.pin_boot_remaining_attempts, CTAP_PIN_PER_BOOT_ATTEMPTS);
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
			"792c78af74cec227d2ff6650723c5cd878638012f970747ae590e7e2b8cec704"
			"6abbd12946d6d26f752394d85927797b8a05baaf40e01c7d0eee062bdb0273e1"
			"869250ffa7920c3c8b8579bcf79147cc"
		>(),
		hex::bytes<
			"f4967b126a3d3c70ed095e90b3f7b1827be7fd7dc4ab2a25b936553528d9d60a"
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
			"40fda15406e29bef471e92be92a84e6d7bf445644b8c199060334e628c04c1f9"
			"a44df3d52e2c448fe46825ae833ae3a8dc60d30db85b273bb63fb79a370c9f39"
			"7803a1079a6f305a75f5601b06e74f32"
		>(),
		hex::bytes<
			"bc8852f6c9b62e9b9d01f648184eea19b73847c0ed4d68cbfe47b3196b475a40"
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
			"f4f843d6fbacfb12bf4bdef2eee61e024ff33b769a4a45164dbea894438186b4"
		>(),
		hex::bytes<
			"bb8c9ca38226db5b057e43e20c9260ae6938dfc5e7436aca34cab95656532d8b"
			"975eab415a6cd9e7fc6e0a21933415134821d76f4bc2b6b9ef3985d7c3c64503"
			"6cbe80a8de28c07695377d3f0e359c06"
		>(),
		hex::bytes<
			"385184ddfbbb0924c399bf05bd72776418c1f2f6e4dff1c37744827e073cc65c"
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
			"40fda15406e29bef471e92be92a84e6d7bf445644b8c199060334e628c04c1f9"
			"a44df3d52e2c448fe46825ae833ae3a8dc60d30db85b273bb63fb79a370c9f39"
			"7803a1079a6f305a75f5601b06e74f32"
		>(),
		hex::bytes<
			"bc8852f6c9b62e9b9d01f648184eea19b73847c0ed4d68cbfe47b3196b475a40"
		>()
	);
	auto params_get_pin_token = create_get_pin_token_v2(
		test_platform_public_key_x,
		test_platform_public_key_y,
		hex::bytes<
			"f4f843d6fbacfb12bf4bdef2eee61e024ff33b769a4a45164dbea894438186b4"
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
		"     44bc108893186e7a75facc9be3e4931e3cbe9888f7e91b08c799fb375292777aca8fc7cf0a0623eae56bfd2c304c4d7f"
	>();
	ASSERT_EQ(response.length, expected_response.size());
	EXPECT_SAME_BYTES_S(response.length, response.data, expected_response.data());
}

} // namespace
