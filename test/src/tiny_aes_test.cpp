#include <gtest/gtest.h>
#include <gtest_custom_assertions.h>
#include <hex.hpp>
#include <aes.hpp>
namespace {

static_assert(TINYAES_ENABLE_AES256 == 1);
static_assert(TINYAES_AES_KEYLEN == 32);
static_assert(TINYAES_AES_BLOCKLEN == 16);

// The current test vectors taken from NIST SP 800-38A
// Recommendation for Block Cipher Modes of Operation: Methods and Techniques
// (https://doi.org/10.6028/NIST.SP.800-38A),
// sections F.2.5 CBC-TINYAES_ENABLE_AES256.Encrypt and F.2.6 CBC-TINYAES_ENABLE_AES256.Decrypt (pages 28-29).
// See also https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES.
constexpr auto key = hex::bytes<
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
>();
static_assert(key.size() == TINYAES_AES_KEYLEN);

constexpr auto iv = hex::bytes<
	"000102030405060708090a0b0c0d0e0f"
>();
static_assert(iv.size() == TINYAES_AES_BLOCKLEN);

constexpr auto plaintext = hex::bytes<
	"6bc1bee22e409f96e93d7e117393172a"
	"ae2d8a571e03ac9c9eb76fac45af8e51"
	"30c81c46a35ce411e5fbc1191a0a52ef"
	"f69f2445df4f9b17ad2b417be66c3710"
>();
static_assert(plaintext.size() % TINYAES_AES_BLOCKLEN == 0);

constexpr auto ciphertext = hex::bytes<
	"f58c4c04d6e5f1ba779eabfb5f7bfbd6"
	"9cfc4e967edb808d679f777bc6702c7d"
	"39f23369a9d9bacfa530e26304231461"
	"b2eb05e2c39be9fcda6c19078c6a9d1b"
>();
static_assert(ciphertext.size() % TINYAES_AES_BLOCKLEN == 0);

TEST(TinyAesTest, TINYAES_ENABLE_AES256CbcEncrypt) {
	struct AES_ctx aes_ctx; // NOLINT(*-pro-type-member-init)
	std::array<uint8_t, plaintext.size()> buffer = plaintext;
	AES_init_ctx_iv(&aes_ctx, key.data(), iv.data());
	AES_CBC_encrypt_buffer(&aes_ctx, buffer.data(), buffer.size());
	EXPECT_SAME_BYTES_S(buffer.size(), buffer.data(), ciphertext.data());
	// the last IV is the last output block
	EXPECT_SAME_BYTES_S(TINYAES_AES_BLOCKLEN, aes_ctx.Iv, &ciphertext[ciphertext.size() - TINYAES_AES_BLOCKLEN]);
}

TEST(TinyAesTest, TINYAES_ENABLE_AES256CbcDecrypt) {
	struct AES_ctx aes_ctx; // NOLINT(*-pro-type-member-init)
	std::array<uint8_t, ciphertext.size()> buffer = ciphertext;
	AES_init_ctx_iv(&aes_ctx, key.data(), iv.data());
	AES_CBC_decrypt_buffer(&aes_ctx, buffer.data(), buffer.size());
	EXPECT_SAME_BYTES_S(buffer.size(), buffer.data(), plaintext.data());
	// the last IV is the last input block (the last block of the ciphertext that is being decrypted)
	EXPECT_SAME_BYTES_S(TINYAES_AES_BLOCKLEN, aes_ctx.Iv, &ciphertext[ciphertext.size() - TINYAES_AES_BLOCKLEN]);
}

}
