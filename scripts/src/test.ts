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

function setOrChangePin(
	oldPinStr: string | undefined,
	newPinStr: string,
	platform: PinUvAuthProtocol = new PinUvAuthProtocolOne(),
	platformPrivateKey: Buffer = TEST_PLATFORM_PRIVATE_KEY,
	authenticatorPublicKey: CoseKey = TEST_AUTHENTICATOR_PUBLIC_KEY,
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

	if (subCommand === 'setPin') {
		const newPin = args[2];
		setOrChangePin(undefined, newPin, protocol);
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
		setOrChangePin(oldPin, newPin, protocol);
	}
}

main(process.argv.slice(2));

