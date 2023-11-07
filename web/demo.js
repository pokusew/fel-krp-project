"use strict";

// https://wicg.github.io/webhid/
// https://github.com/WICG/webhid/blob/main/blocklist.txt

const deviceFilter = {
	vendorId: 0x0483,
	productId: 0x572b,
};
const requestParams = { filters: [deviceFilter] };
const outputReportId = 0x01;
const outputReport = new Uint8Array([42]);

function handleConnectedDevice(e) {
	console.log(`Device connected: ${e.device.productName}`);
}

function handleDisconnectedDevice(e) {
	console.log(`Device disconnected: ${e.device.productName}`);
}

function handleInputReport(e) {
	console.log(`${e.device.productName}: got input report #${e.reportId}`);
	console.log(new Uint8Array(e.data.buffer));
}

navigator.hid.addEventListener('connect', handleConnectedDevice);
navigator.hid.addEventListener('disconnect', handleDisconnectedDevice);

const btnElem = document.querySelector('#demo');

function printCollections(collections, level = 0) {

	// https://developer.mozilla.org/en-US/docs/Web/API/HIDDevice/collections

	const padding = ' '.repeat(level * 2);

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

btnElem.addEventListener('click', () => {

	navigator.hid.requestDevice(requestParams).then((devices) => {
		if (devices.length === 0) {
			return;
		}

		const device = devices[0];

		printCollections(device.collections);

		device.open().then(() => {
			console.log(`Opened device: ${device.productName}`);
			device.addEventListener('inputreport', handleInputReport);
			// device.sendReport(outputReportId, outputReport).then(() => {
			// 	console.log("Sent output report " + outputReportId);
			// });
		});

	});

});


