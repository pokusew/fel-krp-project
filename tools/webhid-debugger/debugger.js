"use strict";

// https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API

// https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API
// https://wicg.github.io/webhid/
// https://github.com/WICG/webhid/blob/main/blocklist.txt

// STATE

// TODO: support more devices
let counter = 1;
let lastDevice = null;

// UI

const outputElem = document.querySelector('#log');

function clearLog() {
	outputElem.textContent = '';
}

function appendLog(message = '') {
	outputElem.textContent += message + '\n';
}

const dialogElem = document.querySelector('dialog#dialog');

function showMessage(message) {
	dialogElem.querySelector('#message').textContent = message;
	dialogElem.showModal();
}

document.querySelector('#allow-access').addEventListener('click', (event) => {
	requestPermissions();
});

document.querySelector('#send').addEventListener('click', (event) => {
	if (lastDevice === null) {
		return;
	}
	demoSend(lastDevice);
});

document.querySelector('#clear-log').addEventListener('click', (event) => {
	clearLog();
});

// LOGIC

navigator.hid.addEventListener('connect', handleConnectedDevice);
navigator.hid.addEventListener('disconnect', handleDisconnectedDevice);

async function requestPermissions() {

	const deviceFilter = {
		vendorId: 0x1209,
		productId: 0x0001,
	};

	const requestParams = { filters: [deviceFilter] };

	try {
		const devices = await navigator.hid.requestDevice(requestParams);
		devices.forEach(handleDevice);
	} catch (err) {
		document.querySelector('dialog#dialog').showModal();
		showMessage(err.toString());
	}

}

async function handleDevice(device) {

	appendLog(`handleDevice: ${device.productName} (vendorId=${device.vendorId}, productId=${device.productId})`);

	printCollections(device.collections);

	if (!device.opened) {
		await device.open();
	} else {
		appendLog('device already open');
	}

	lastDevice = device;

	device.addEventListener('inputreport', handleInputReport);

	appendLog();

}

function handleConnectedDevice(e) {
	const device = e.device;
	appendLog(`device connected: ${device.productName} (vendorId=${device.vendorId}, productId=${device.productId})`);
	handleDevice(device);
}

function handleDisconnectedDevice(e) {
	const device = e.device;
	if (lastDevice === device) {
		lastDevice = null;
	}
	appendLog(`device disconnected: ${device.productName} (vendorId=${device.vendorId}, productId=${device.productId})`);
	appendLog();
}

function handleInputReport(e) {
	const device = e.device;
	appendLog(`${device.productName} (vendorId=${device.vendorId}, productId=${device.productId}):`);
	appendLog(`got input report #${e.reportId} size = ${e.data.byteLength}`)
	appendLog(new Uint8Array(e.data.buffer));
	appendLog();
}

function printCollections(collections, level = 1) {

	// https://developer.mozilla.org/en-US/docs/Web/API/HIDDevice/collections

	const padding = '-'.repeat(level * 2);

	for (const collection of collections) {
		// A HID collection includes usage, usage page, reports, and subcollections.
		appendLog(`${padding} Usage: ${collection.usage}`);
		appendLog(`${padding} Usage page: ${collection.usagePage}`);

		for (const inputReport of collection.inputReports) {
			appendLog(`${padding} Input report: #${inputReport.reportId}`);
			// Loop through inputReport.items
		}

		for (const outputReport of collection.outputReports) {
			appendLog(`${padding} Output report: #${outputReport.reportId}`);
			// Loop through outputReport.items
		}

		for (const featureReport of collection.featureReports) {
			appendLog(`${padding} Feature report: #${featureReport.reportId}`);
			// Loop through featureReport.items
		}

		// Loop through subcollections with collection.children
		printCollections(collection.children, level + 1);
	}

}

async function demoSend(device) {

	const value = counter & 0xFF;

	const data = new Uint8Array([
		0xa1,
		0xb2,
		0xc3,
		0xc4,
		value,
	]);

	try {
		await device.sendReport(0, data);
	} catch (err) {
		appendLog(`an error while sending data: ${err.toString()}`);
		appendLog();
		return;
	}

	counter++;

	appendLog(`sent counter = ${value}`);
	appendLog();

}

navigator.hid.addEventListener('connect', handleConnectedDevice);
navigator.hid.addEventListener('disconnect', handleDisconnectedDevice);

async function reconnect() {
	const devices = await navigator.hid.getDevices();
	devices.forEach(handleDevice);
}

reconnect();


