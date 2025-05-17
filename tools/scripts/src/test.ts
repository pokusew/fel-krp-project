import {
	PinUvAuthProtocol,
	PinUvAuthProtocolOne,
	PinUvAuthProtocolTwo,
	createPinUvAuthProtocolEcdhCoseKey,
	computeSha256Digest,
	CoseKey,
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

function processPin(pin: string, name = 'pin'): ProcessedPin {
	console.log(`${name} = '${pin}'`);
	const bytes = Buffer.from(pin, 'utf-8');
	hex('  bytes', bytes);
	const hash = computeSha256Digest(bytes);
	hex('  hash', hash);
	const padded = padPin(bytes);
	hex('  padded', padded);
	return { pin, bytes, padded, hash };
}

const TEST_AUTHENTICATOR_PUBLIC_KEY_V1 = createPinUvAuthProtocolEcdhCoseKey({
	x: Buffer.from(
		'78b110adb2f168a39a5fa453c71e86a64ed95b909b87d9ccb0e635ae3ed1517b',
		'hex',
	),
	y: Buffer.from(
		'1d1b7cf464db2b5df507e4848873a35ea18882336e0e7fe6524e18b573215fc3',
		'hex',
	),
});
const TEST_AUTHENTICATOR_PUBLIC_KEY_V2 = createPinUvAuthProtocolEcdhCoseKey({
	x: Buffer.from(
		'f09d2dcc4d511c5a3fb5b5810301e34aae76a1d372e2595e6f2843258525d24f',
		'hex',
	),
	y: Buffer.from(
		'dbb6ce2d43ccded46901977184a23bc66a6c5adf27c522c389e71c09e4c05281',
		'hex',
	),
});

const TEST_PLATFORM_PRIVATE_KEY = Buffer.from(
	'b6a7164827e98933906aa13b90dd8bf6a15989a3419d90ecc1cde95a80aefb6c',
	'hex',
);

function setOrChangePin(
	oldPinStr: string | undefined,
	newPinStr: string,
	platform: PinUvAuthProtocol = new PinUvAuthProtocolOne(),
	platformPrivateKey: Buffer,
	authenticatorPublicKey: CoseKey,
) {
	console.log(oldPinStr === undefined ? '--- setPin ---' : '--- changePin ---');

	const oldPin = oldPinStr !== undefined ? processPin(oldPinStr, 'oldPin') : undefined;
	const newPin = processPin(newPinStr, 'newPin');

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

	const message: Buffer[] = [newPicEnc];

	if (oldPin !== undefined) {
		const pinHashEnc = platform.encrypt(sharedSecret, oldPin.hash.subarray(0, 16));
		hex('pinHashEnc', pinHashEnc);
		message.push(pinHashEnc);
	}

	const pinUvAuthParam = platform.authenticate(sharedSecret, Buffer.concat(message));
	hex('pinUvAuthParam', pinUvAuthParam);
}

const USAGE = `usage:
  {v1|v2} setPin {newPin}
  {v1|v2} changePin {oldPin} {newPin}`;

function main(args: string[]) {
	if (args.length < 3) {
		console.error(`missing required arguments`);
		console.error(USAGE);
		process.exit(1);
	}

	const [version, subCommand] = args;

	if (version !== 'v1' && version !== 'v2') {
		console.error(`invalid protocol version '${version}' given`);
		console.error(USAGE);
		process.exit(1);
	}

	if (subCommand !== 'setPin' && subCommand !== 'changePin') {
		console.error(`invalid subCommand name '${version}' given`);
		console.error(USAGE);
		process.exit(1);
	}

	const protocol: PinUvAuthProtocol =
		version === 'v1' ? new PinUvAuthProtocolOne() : new PinUvAuthProtocolTwo();
	const authenticatorPublicKey: CoseKey =
		version === 'v1'
			? TEST_AUTHENTICATOR_PUBLIC_KEY_V1
			: TEST_AUTHENTICATOR_PUBLIC_KEY_V2;

	if (subCommand === 'setPin') {
		const newPin = args[2];
		setOrChangePin(
			undefined,
			newPin,
			protocol,
			TEST_PLATFORM_PRIVATE_KEY,
			authenticatorPublicKey,
		);
		return;
	}

	if (subCommand === 'changePin') {
		if (process.argv.length < 4) {
			console.error(`missing required arguments`);
			console.error(USAGE);
			process.exit(1);
		}
		const oldPin = args[2];
		const newPin = args[3];
		setOrChangePin(
			oldPin,
			newPin,
			protocol,
			TEST_PLATFORM_PRIVATE_KEY,
			authenticatorPublicKey,
		);
	}
}

main(process.argv.slice(2));
