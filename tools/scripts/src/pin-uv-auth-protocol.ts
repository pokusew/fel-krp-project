import type { ECDH } from 'node:crypto';
import {
	createCipheriv,
	createDecipheriv,
	createECDH,
	createHash,
	createHmac,
	randomBytes,
	hkdfSync,
} from 'node:crypto';
import assert from 'node:assert/strict';

/**
 * SHA-256 (SHA-2)
 *
 * https://en.wikipedia.org/wiki/SHA-2
 *
 * * SHA-256
 *   * 64 bytes (512 bits) internal SHA-256 block size
 *   * 32 bytes (256 bits) output
 *
 * @param data data (arbitrary length)
 * @returns hash (aka digest) (32 bytes)
 */
export function computeSha256Digest(data: Buffer): Buffer {
	const hash = createHash('sha256');
	hash.update(data);
	const digest = hash.digest();
	assert.equal(digest.length, 32);
	return digest;
}

/**
 * HMAC-SHA-256
 *
 * https://en.wikipedia.org/wiki/HMAC
 *
 * The `key` should have ideally the internal hash block size (SHA-256 = 64 bytes),
 * but any size is accepted and the given key is internally shortened by hashing or expanded by padding.
 *
 * * SHA-256
 *   * 64 bytes (512 bits) internal SHA-256 block size
 *   * 32 bytes (256 bits) output
 * @param key ideally 64 bytes
 * @param data data (arbitrary length)
 * @returns hmac (aka digest or hash) (32 bytes)
 */
export function computeHmacSha256Digest(key: Buffer, data: Buffer) {
	const hmac = createHmac('sha256', key);
	hmac.update(data);
	const digest = hmac.digest();
	assert.equal(digest.length, 32);
	return digest;
}

export interface CoseKey {
	kty: number;
	alg: number;
	crv: number;
	x: Buffer;
	y: Buffer;
}

export interface Encapsulation {
	sharedSecret: Buffer;
	publicKey: CoseKey;
}

/**
 * [6.5.4. PIN/UV Auth Protocol Abstract Definition](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-puaprot-abstract-dfn)
 *
 * The platform interface:
 */
export interface PinUvAuthProtocolPlatform {
	/**
	 * This is run by the platform when starting a series of transactions with a specific authenticator.
	 */
	initialize(privateKey?: Buffer): void;

	/**
	 * Generates an encapsulation for the authenticator's public key
	 * and returns the message to transmit and the shared secret.
	 */
	encapsulate(peerCoseKey: CoseKey): Encapsulation;

	/**
	 * Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
	 * The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
	 */
	encrypt(key: Buffer, plaintext: Buffer): Buffer;

	/**
	 * Decrypts a ciphertext and returns the plaintext, which may be shorter than the ciphertext.
	 * The ciphertext is restricted to being a multiple of the AES block size (16 bytes) in length.
	 */
	decrypt(key: Buffer, ciphertext: Buffer): Buffer;

	/**
	 * Computes a MAC of the given message.
	 */
	authenticate(key: Buffer, message: Buffer): Buffer;
}

/**
 * [6.5.4. PIN/UV Auth Protocol Abstract Definition](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-puaprot-abstract-dfn)
 *
 * The authenticator interface:
 */
export interface PinUvAuthProtocolAuthenticator {
	/**
	 * This process is run by the authenticator at power-on.
	 */
	initialize(privateKey?: Buffer): void;

	/**
	 * Generates a fresh public key.
	 */
	regenerate(privateKey?: Buffer): void;

	/**
	 * Generates a fresh pinUvAuthToken.
	 */
	resetPinUvAuthToken(): void;

	/**
	 * Returns the authenticator’s public key as a COSE_Key structure.
	 */
	getPublicKey(): CoseKey;

	/**
	 * Processes the output of encapsulate from the peer and produces a shared secret, known to both platform and authenticator.
	 */
	decapsulate(peerCoseKey: CoseKey): Buffer;

	/**
	 * Decrypts a ciphertext, using sharedSecret as a key, and returns the plaintext.
	 */
	decrypt(sharedSecret: Buffer, ciphertext: Buffer): Buffer;

	/**
	 * Verifies that the signature is a valid MAC for the given message. If the key parameter value is the current pinUvAuthToken, it also checks whether the pinUvAuthToken is in use or not.
	 */
	verify(key: Buffer, message: Buffer, signature: Buffer): void;
}

export interface PinUvAuthProtocol
	extends PinUvAuthProtocolPlatform,
		PinUvAuthProtocolAuthenticator {
	getPrivateKey(): Buffer;

	getSharedSecret(peerCoseKey: CoseKey): Buffer;
}

const PIN_UV_AUTH_TOKEN_SIZE = 32;

export function createPinUvAuthProtocolEcdhCoseKey({
	x,
	y,
}: Pick<CoseKey, 'x' | 'y'>): CoseKey {
	assert.equal(x.length, 32);
	assert.equal(y.length, 32);
	return {
		kty: 2, // (EC2)
		alg: -25, // (although this is not the algorithm actually used)
		crv: 1, // (P-256)
		x, // 32-byte, big-endian encoding of the x-coordinate of xB (the key agreement key's public point)
		y, // 32-byte, big-endian encoding of the y-coordinate of xB
	};
}

/**
 * Encrypts the given data using AES-256-CBC.
 *
 * No padding is performed. The plaintext is required to be a multiple of the AES block length (16 bytes).
 *
 * @param key 256-bit key (32 bytes)
 * @param iv IV (aka initialization vector) (16 bytes)
 * @param plaintext data to encrypt, required to be a multiple of the AES block length (16 bytes)
 * @returns ciphertext (will have the same size as the plaintext)
 */
export function aes256CbcEncrypt(key: Buffer, iv: Buffer, plaintext: Buffer): Buffer {
	const encipher = createCipheriv('aes-256-cbc', key, iv);
	encipher.setAutoPadding(false);
	return Buffer.concat([encipher.update(plaintext), encipher.final()]);
}

/**
 * Decrypts the given data using AES-256-CBC.
 *
 * No padding is performed. The ciphertext is required to be a multiple of the AES block length (16 bytes).
 *
 * @param key 256-bit key (32 bytes)
 * @param iv IV (aka initialization vector) (16 bytes)
 * @param ciphertext data to decrypt, required to be a multiple of the AES block length (16 bytes)
 * @returns plaintext (will have the same size as the ciphertext)
 */
export function aes256CbcDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
	const decipher = createDecipheriv('aes-256-cbc', key, iv);
	decipher.setAutoPadding(false);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// AES-256 -> 256-bit key (32 bytes)
// all AES variants have a block size (input/output size) of 16 bytes (128 bits)
const AES_256_CBC_ALL_ZERO_IV = Buffer.allocUnsafe(16).fill(0);

/**
 * [6.5.6. PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1)
 */
export class PinUvAuthProtocolOne implements PinUvAuthProtocol {
	static readonly SHARED_SECRET_SIZE: number = 32;

	private ecdh: ECDH;
	private pinUvAuthToken: Buffer | null;

	constructor() {
		// prime256v1 OpenSSL's name for secp256r1
		this.ecdh = createECDH('prime256v1');
		this.pinUvAuthToken = null;
	}

	initialize(privateKey?: Buffer): void {
		this.regenerate(privateKey);
		this.resetPinUvAuthToken();
	}

	regenerate(privateKey?: Buffer): void {
		if (privateKey !== undefined) {
			this.ecdh.setPrivateKey(privateKey);
			// publicKey is automatically computed
		} else {
			this.ecdh.generateKeys();
		}
	}

	resetPinUvAuthToken(): void {
		this.pinUvAuthToken = randomBytes(PIN_UV_AUTH_TOKEN_SIZE);
	}

	getPrivateKey(): Buffer {
		return this.ecdh.getPrivateKey();
	}

	getPublicKey(): CoseKey {
		// OpenSSL returns ECDH public keys with the 0x04 prefix
		const publicKeyWithPrefix = this.ecdh.getPublicKey();
		assert.equal(publicKeyWithPrefix.length, 65);
		const publicKey = publicKeyWithPrefix.subarray(1);
		assert.equal(publicKey.length, 64);
		const x = publicKey.subarray(0, 32);
		const y = publicKey.subarray(32, 64);
		return createPinUvAuthProtocolEcdhCoseKey({ x, y });
	}

	kdf(sharedPointZ: Buffer): Buffer {
		const sharedSecret = computeSha256Digest(sharedPointZ);
		assert.equal(sharedSecret.length, PinUvAuthProtocolOne.SHARED_SECRET_SIZE);
		return sharedSecret;
	}

	getSharedSecret(peerCoseKey: CoseKey): Buffer {
		const peerPublicKey = Buffer.concat([
			Buffer.from([0x04]),
			peerCoseKey.x,
			peerCoseKey.y,
		]);
		const sharedPointZ = this.ecdh.computeSecret(peerPublicKey);
		return this.kdf(sharedPointZ);
	}

	encapsulate(peerCoseKey: CoseKey): Encapsulation {
		return {
			publicKey: this.getPublicKey(),
			sharedSecret: this.getSharedSecret(peerCoseKey),
		};
	}

	decapsulate(peerCoseKey: CoseKey): Buffer {
		return this.getSharedSecret(peerCoseKey);
	}

	authenticate(key: Buffer, message: Buffer): Buffer {
		// Return the first 16 bytes of the result of computing HMAC-SHA-256 with the given key and message.
		const digest = computeHmacSha256Digest(key, message);
		return digest.subarray(0, 16);
	}

	verify(key: Buffer, message: Buffer, signature: Buffer): void {
		const digest = computeHmacSha256Digest(key, message);
		const digestFirst16Bytes = digest.subarray(0, 16);
		if (signature.length !== 16 || !signature.equals(digestFirst16Bytes)) {
			throw new Error('Invalid signature!');
		}
	}

	encrypt(key: Buffer, plaintext: Buffer): Buffer {
		return aes256CbcEncrypt(key, AES_256_CBC_ALL_ZERO_IV, plaintext);
	}

	decrypt(key: Buffer, ciphertext: Buffer): Buffer {
		return aes256CbcDecrypt(key, AES_256_CBC_ALL_ZERO_IV, ciphertext);
	}
}

const HKDF_SHA_256_ZERO_SALT = Buffer.allocUnsafe(32).fill(0);

/**
 * [6.5.7. PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto2)
 */
export class PinUvAuthProtocolTwo extends PinUvAuthProtocolOne {
	static readonly SHARED_SECRET_SIZE: number = 64;

	kdf(sharedPointZ: Buffer): Buffer {
		const hmacKey = hkdfSync(
			'sha256',
			sharedPointZ,
			HKDF_SHA_256_ZERO_SALT,
			'CTAP2 HMAC key',
			32,
		);
		const aesKey = hkdfSync(
			'sha256',
			sharedPointZ,
			HKDF_SHA_256_ZERO_SALT,
			'CTAP2 AES key',
			32,
		);
		const sharedSecret = Buffer.concat([Buffer.from(hmacKey), Buffer.from(aesKey)]);
		assert.equal(hmacKey.byteLength, 32);
		assert.equal(aesKey.byteLength, 32);
		assert.equal(sharedSecret.length, PinUvAuthProtocolTwo.SHARED_SECRET_SIZE);
		return sharedSecret;
	}

	authenticate(key: Buffer, message: Buffer): Buffer {
		// If key is longer than 32 bytes, discard the excess.
		// This selects the HMAC-key portion of the shared secret (see kdf() above).
		// When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.
		const hmacKey = key.length >= 32 ? key.subarray(0, 32) : key;
		const digest = computeHmacSha256Digest(hmacKey, message);
		assert.equal(digest.length, 32);
		return digest;
	}

	verify(key: Buffer, message: Buffer, signature: Buffer): void {
		// If key is longer than 32 bytes, discard the excess.
		// This selects the HMAC-key portion of the shared secret (see kdf() above).
		// When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.
		const hmacKey = key.length >= 32 ? key.subarray(0, 32) : key;
		const digest = computeHmacSha256Digest(hmacKey, message);
		if (!signature.equals(digest)) {
			throw new Error('Invalid signature!');
		}
	}

	extractAesKey(sharedSecret: Buffer): Buffer {
		assert.equal(sharedSecret.length, PinUvAuthProtocolTwo.SHARED_SECRET_SIZE);
		return sharedSecret.subarray(32, 64);
	}

	encrypt(key: Buffer, plaintext: Buffer): Buffer {
		const aesKey = this.extractAesKey(key);
		const iv = randomBytes(16);
		const ct = aes256CbcEncrypt(aesKey, iv, plaintext);
		return Buffer.concat([iv, ct]);
	}

	decrypt(key: Buffer, ciphertext: Buffer): Buffer {
		const aesKey = this.extractAesKey(key);
		if (ciphertext.length < 16) {
			throw new Error(
				'The ciphertext (which is iv || ct) in decrypt() in PIN/UV Auth Protocol v2must be at least 16 bytes.',
			);
		}
		const iv = ciphertext.subarray(0, 16);
		const ct = ciphertext.subarray(16);
		return aes256CbcDecrypt(aesKey, iv, ct);
	}
}
