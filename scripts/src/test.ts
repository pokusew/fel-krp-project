import {
	PinUvAuthProtocolOne,
	createPinUvAuthProtocolEcdhCoseKey,
	computeSha256Digest,
	CoseKey,
	PinUvAuthProtocol,
} from './pin-uv-auth-protocol.js';
import assert from 'node:assert/strict';

function hex(name: string, data: Buffer) {
	console.log(`${name} (${data.length} bytes)\n  `, data.toString('hex'));
}

function padPin(pinBytes: Buffer): Buffer {
	assert(4 <= pinBytes.length && pinBytes.length <= 63);
	const paddedPin = Buffer.allocUnsafe(64).fill(0);
	pinBytes.copy(paddedPin, 0);
	return paddedPin;
}

interface ProcessedPin {
	pin: string;
	bytes: Buffer;
	hash: Buffer;
	padded: Buffer;
}

function processPin(pin: string): ProcessedPin {
	console.log(`pin = '${pin}'`);
	const bytes = Buffer.from(pin, 'utf-8');
	hex('  bytes', bytes);
	const hash = computeSha256Digest(bytes);
	hex('  hash', hash);
	const padded = padPin(bytes);
	hex('  padded', padded);
	return { pin, bytes, padded, hash };
}

const TEST_AUTHENTICATOR_PUBLIC_KEY = createPinUvAuthProtocolEcdhCoseKey({
	x: Buffer.from(
		'c006f1253c019a3fccde54d159f8da812b218948c8746e46944545ee717867c6',
		'hex',
	),
	y: Buffer.from(
		'23cefbf7f94271a5b7159de7a0351705a7d321459c82ce96858351fa395b40a7',
		'hex',
	),
});

const TEST_PLATFORM_PRIVATE_KEY = Buffer.from(
	'b6a7164827e98933906aa13b90dd8bf6a15989a3419d90ecc1cde95a80aefb6c',
	'hex',
);

function setPin(
	pin: string,
	platform: PinUvAuthProtocol = new PinUvAuthProtocolOne(),
	platformPrivateKey: Buffer = TEST_PLATFORM_PRIVATE_KEY,
	authenticatorPublicKey: CoseKey = TEST_AUTHENTICATOR_PUBLIC_KEY,
) {
	console.log('--- setPin ---');

	const newPin = processPin(pin);

	platform.initialize(platformPrivateKey);

	hex('platformPrivateKey', platform.getPrivateKey());
	{
		const { x, y } = platform.getPublicKey();
		hex('platformPublicKey.x', x);
		hex('platformPublicKey.y', y);
	}

	const sharedSecret = platform.getSharedSecret(authenticatorPublicKey);
	hex('sharedSecret', sharedSecret);

	const newPicEnc = platform.encrypt(sharedSecret, newPin.padded);
	hex('newPicEnc', newPicEnc);
	const pinUvAuthParam = platform.authenticate(sharedSecret, newPicEnc);
	hex('pinUvAuthParam', pinUvAuthParam);
}

function main() {

	if (process.argv.length < 3) {
		console.error(`missing required argument pin`);
		process.exit(1);
	}

	const pin = process.argv[2];

	setPin(pin);

}

main();

