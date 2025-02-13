#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
extern "C" {
#include <ctap.h>
#include <utils.h>
}
namespace {

class CtapClientPinTest : public testing::Test {
protected:
	ctap_state_t ctap{};
	uint8_t response_status_code{};
	uint16_t response_data_length{};
	uint8_t *response_data{};
	uint8_t status{};

	CtapClientPinTest() {

		// set a constant seed to generate predictable random numbers by rand()
		// ctap_generate_rng() uses rand() in unit tests
		srand(13); // NOLINT(*-msc51-cpp)

		ctap_init(&ctap);

	}

	template<size_t N>
	void test_ctap_request(const std::array<uint8_t, N> &request) {
		status = ctap_request(
			&ctap,
			N, request.data(),
			&response_status_code, &response_data_length, &response_data
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
		"09" //   unsigned(9)
	>();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_ERR_INVALID_SUBCOMMAND);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
}

TEST_F(CtapClientPinTest, GetPinRetries) {
	// 0x06 {1: 1, 2: 1}
	auto request = hex::bytes<"06 a2 01 01 02 01">();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	// {3: 8, 4: false}
	auto expected_response = hex::bytes<"a2 03 08 04 f4">();
	ASSERT_EQ(response_data_length, expected_response.size());
	EXPECT_SAME_BYTES_S(response_data_length, response_data, expected_response.data());
}

TEST_F(CtapClientPinTest, GetKeyAgreement) {
	// 0x06 {1: 1, 2: 2}
	auto request = hex::bytes<"06 a2 01 01 02 02">();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	auto expected_response = hex::bytes<
		// {
		//     1: {
		//         1: 2,
		//         3: -25_0,
		//         -1: 1,
		//         -2: h'c006f1253c019a3fccde54d159f8da812b218948c8746e46944545ee717867c6',
		//         -3: h'23cefbf7f94271a5b7159de7a0351705a7d321459c82ce96858351fa395b40a7',
		//     },
		// }
		"a1"
		"01"
		"a5"
		"01 02"
		"03 38 18"
		"20 01"
		"21 58 20"
		"c006f1253c019a3fccde54d159f8da812b218948c8746e46944545ee717867c6"
		"22 58 20"
		"23cefbf7f94271a5b7159de7a0351705a7d321459c82ce96858351fa395b40a7"
	>();
	dump_hex(response_data, response_data_length);
	ASSERT_EQ(response_data_length, expected_response.size());
	EXPECT_SAME_BYTES_S(response_data_length, response_data, expected_response.data());
}

TEST_F(CtapClientPinTest, SetPin1234) {
	auto pin = hex::bytes<"31323334">();
	EXPECT_EQ(ctap.persistent.is_pin_set, false);
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
		//     4: h'{pinUvAuthParam (0x04)}',
		//     5: h'{newPinEnc (0x05)}',
		// }
		"a5"
		"  01 01"
		"  02 03"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
		"       22 5820" // y (32 bytes)
		"          d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
		"  04 50" // pinUvAuthParam (0x04) (16 bytes)
		"     f5d31443c94ba810aed7d02d4fce816f"
		"  05 5840" // newPinEnc (0x05) (64 bytes)
		"     ceb8b1e368e647b2336f9e8c3e153e268bdec21eb33d93235650d9e6ae245f359155836973598fba7d5709f0f47bfcf747d99c117642e1f1286765f3fa96a238"
	>();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
	EXPECT_EQ(ctap.persistent.is_pin_set, true);
	auto pin_hash = hex::bytes<
		"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
	>();
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

TEST_F(CtapClientPinTest, SetPinOneCodePoint) {
	auto pin = hex::bytes<"f09f988c">();
	EXPECT_EQ(ctap.persistent.is_pin_set, false);
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
		//     4: h'{pinUvAuthParam (0x04)}',
		//     5: h'{newPinEnc (0x05)}',
		// }
		"a5"
		"  01 01"
		"  02 03"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
		"       22 5820" // y (32 bytes)
		"          d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
		"  04 50" // pinUvAuthParam (0x04) (16 bytes)
		"     38b6f403a3e87602a8c9678b2eb437f7"
		"  05 5840" // newPinEnc (0x05) (64 bytes)
		"     ce7264d4045a30811eafb155d265b345e048acbfcf8ff7206fa9cf9bfb891893f70e3d8d96c75407a032de1fe0682bc040680ff6c4cd29e1850baca3bc56ddaf"
	>();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_ERR_PIN_POLICY_VIOLATION);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
	EXPECT_EQ(ctap.persistent.is_pin_set, false);
}

TEST_F(CtapClientPinTest, SetPinEmoji) {
	auto pin = hex::bytes<"f09f988cf09f918df09f8fbb34">();
	EXPECT_EQ(ctap.persistent.is_pin_set, false);
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
		//     4: h'{pinUvAuthParam (0x04)}',
		//     5: h'{newPinEnc (0x05)}',
		// }
		"a5"
		"  01 01"
		"  02 03"
		"  03 a5"
		"       01 02"
		"       03 3818"
		"       20 01"
		"       21 5820" // x (32 bytes)
		"          bcfd95db7be64d2dc19d450b87635f9dfc5a4a7c872c3a66cc98e2f724799095"
		"       22 5820" // y (32 bytes)
		"          d55c3641e99a6ca1ebe9bc6600df3de0f2e3be334359c7422bff873f341f379b"
		"  04 50" // pinUvAuthParam (0x04) (16 bytes)
		"     757a4665ee9c2b5a07bb96faf7e2e576"
		"  05 5840" // newPinEnc (0x05) (64 bytes)
		"     cfeca45907a8f0600fd4c6fd8dd3281d0431f38a85eb1b32020e5c1f31e05d7248b53c4a600c9177ca928b584a710534b8a03309ebb5c371dc2502538e68b580"
	>();
	test_ctap_request(request);
	EXPECT_EQ(status, CTAP2_OK);
	EXPECT_EQ(response_status_code, status);
	EXPECT_EQ(response_data_length, 0);
	EXPECT_EQ(ctap.persistent.is_pin_set, true);
	auto pin_hash = hex::bytes<
		"b9157af8f2947a41039aaa274f1568a691b7494531d93282a73ff993d7b99494"
	>();
	static_assert(sizeof(ctap.persistent.pin_hash) <= pin_hash.size());
	EXPECT_SAME_BYTES(ctap.persistent.pin_hash, pin_hash.data());
}

} // namespace
