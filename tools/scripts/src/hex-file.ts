// This script implements utils for generating Intel HEX files (.hex).
// See https://en.wikipedia.org/wiki/Intel_HEX.
// The .hex files are commonly used for transferring firmware images of embedded devices.
// NUCLEO-H533RE's built-in STLINK-V3EC supports flashing .hex files using its USB mass storage interface.

const NO_DATA = Buffer.from([]);

// https://en.wikipedia.org/wiki/Intel_HEX#Record_types
const RECORD_TYPE_DATA = 0x00;
const RECORD_TYPE_END_OF_FILE = 0x01;
const RECORD_TYPE_EXTENDED_SEGMENT_ADDRESS = 0x02;
const RECORD_TYPE_START_SEGMENT_ADDRESS = 0x03;
const RECORD_TYPE_EXTENDED_LINEAR_ADDRESS = 0x04;
const RECORD_TYPE_START_LINEAR_ADDRESS = 0x05;

type RecordType =
	| typeof RECORD_TYPE_DATA
	| typeof RECORD_TYPE_END_OF_FILE
	| typeof RECORD_TYPE_EXTENDED_SEGMENT_ADDRESS
	| typeof RECORD_TYPE_START_SEGMENT_ADDRESS
	| typeof RECORD_TYPE_EXTENDED_LINEAR_ADDRESS
	| typeof RECORD_TYPE_START_LINEAR_ADDRESS;

function toHex(value: number, length: number = 2) {
	return value.toString(16).toUpperCase().padStart(length, '0');
}

// https://en.wikipedia.org/wiki/Intel_HEX#Format
// https://en.wikipedia.org/wiki/Intel_HEX#Record_structure
function record(type: RecordType, address: number, data: Buffer) {
	if (!Number.isInteger(address) || address > 0xffff) {
		throw new Error('Invalid address');
	}

	if (!Number.isInteger(type) || type > 0xff) {
		throw new Error('Invalid type');
	}

	if (data.length > 0xff) {
		throw new Error('data.length must be <= 0xFF');
	}

	let checksum = data.length + (address & 0xff) + ((address >>> 8) & 0xff) + type;

	for (let i = 0; i < data.length; i++) {
		checksum += data[i];
	}

	checksum = (255 + 1 - checksum) & 0xff;

	return `:${toHex(data.length)}${toHex(address, 4)}${toHex(type)}${data.toString('hex').toUpperCase()}${toHex(checksum, 2)}`;
}

function extendedLinearAddressRecord(upper16bits: number) {
	const data = Buffer.allocUnsafe(2);
	data.writeInt16BE(upper16bits);
	return record(RECORD_TYPE_EXTENDED_LINEAR_ADDRESS, 0x0000, data);
}

const END_OF_FILE_RECORD = record(RECORD_TYPE_END_OF_FILE, 0x0000, NO_DATA);

function println(data: string) {
	process.stdout.write(data);
	process.stdout.write('\n');
}

// generate .hex that will clear the 8KB sector 0 in bank 2
const ZERO_16_FF = Buffer.allocUnsafe(16).fill(0xff);
// 0x0804_0000 = bank 2, 8KB sector 0
println(extendedLinearAddressRecord(0x0804));
for (let i = 0; i < 8 * 1024; i += 16) {
	println(record(RECORD_TYPE_DATA, i, ZERO_16_FF));
}
println(END_OF_FILE_RECORD);

// NUCLEO-H533RE's built-in STLINK-V3EC does NOT support flashing to the high-cycling flash memory area.
// const ZERO_4 = Buffer.allocUnsafe(4).fill(0xFF);
// // 0x0900_C000 = bank 2, 6KB high-cycling sector 0
// println(extendedLinearAddressRecord(0x0900));
// for (let i = 0; i < 6 * 1024; i += 4) {
// 	println(record(RECORD_TYPE_DATA, 0xC000 + i, ZERO_4));
// }
// println(END_OF_FILE_RECORD);

// const ZERO_16_FF = Buffer.allocUnsafe(16).fill(0xff);
// // 0x0807_0000 = bank 2, 8KB sector 24 (corresponds to the 6KB high-cycling sector 0)
// // (only works if the high-cycling flash memory area is not enabled)
// println(extendedLinearAddressRecord(0x0807));
// for (let i = 0; i < 8 * 1024; i += 16) {
// 	println(record(RECORD_TYPE_DATA, i, ZERO_16_FF));
// }
// println(END_OF_FILE_RECORD);
