"use strict";

// https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API

// https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API
// https://wicg.github.io/webhid/
// https://github.com/WICG/webhid/blob/main/blocklist.txt

// UI

const dialogElem = document.querySelector('dialog#dialog');

const btnElem = document.querySelector('#demo');

function showMessage(message) {
	dialogElem.querySelector('#message').textContent = message;
	dialogElem.showModal();
}

btnElem.addEventListener('click', (event) => {
	requestPermissions();
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

	console.log(`handleDevice: ${device.productName} (vendorId=${device.vendorId}, productId=${device.productId})`);

	printCollections(device.collections);

	if (!device.opened) {
		await device.open();
	}

	device.addEventListener('inputreport', handleInputReport);

}

function handleConnectedDevice(e) {
	console.log(`Device connected: ${e.device.productName}`);
}

function handleDisconnectedDevice(e) {
	console.log(`Device disconnected: ${e.device.productName}`);
}

function handleInputReport(e) {
	console.log(`${device.productName} (vendorId=${device.vendorId}, productId=${device.productId}): got input report #${e.reportId}`);
	console.log(new Uint8Array(e.data.buffer));
}

function printCollections(collections, level = 1) {

	// https://developer.mozilla.org/en-US/docs/Web/API/HIDDevice/collections

	const padding = '-'.repeat(level * 2);

	for (const collection of collections) {
		// A HID collection includes usage, usage page, reports, and subcollections.
		console.log(`${padding} Usage: ${collection.usage}`);
		console.log(`${padding} Usage page: ${collection.usagePage}`);

		for (const inputReport of collection.inputReports) {
			console.log(`${padding} Input report: #${inputReport.reportId}`);
			// Loop through inputReport.items
		}

		for (const outputReport of collection.outputReports) {
			console.log(`${padding} Output report: #${outputReport.reportId}`);
			// Loop through outputReport.items
		}

		for (const featureReport of collection.featureReports) {
			console.log(`${padding} Feature report: #${featureReport.reportId}`);
			// Loop through featureReport.items
		}

		// Loop through subcollections with collection.children
		printCollections(collection.children, level + 1);
	}

}

navigator.hid.addEventListener('connect', handleConnectedDevice);
navigator.hid.addEventListener('disconnect', handleDisconnectedDevice);

async function reconnect() {
	const devices = await navigator.hid.getDevices();
	devices.forEach(handleDevice);
}

reconnect();


