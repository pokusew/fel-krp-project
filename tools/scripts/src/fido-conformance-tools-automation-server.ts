import { createServer } from 'node:http';
import { setTimeout } from 'node:timers/promises';
import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { SerialPort } from 'serialport';

const RESULTS_DIR = 'results.local';

function createFidoConformanceToolsServer(port: SerialPort) {
	// https://nodejs.org/docs/latest-v20.x/api/http.html
	const server = createServer(async (req, res) => {
		const path = req.url;

		// https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Automation.md#automation-api

		console.log(`request`, req.method, path);

		if (path === '/conformance/userpresence') {
			port.write('u');
			await setTimeout(10);
			res.statusCode = 201;
			res.end();
			return;
		}

		if (path === '/conformance/powercycle') {
			port.write('b');
			await setTimeout(10);
			res.statusCode = 201;
			res.end();
			return;
		}

		if (path === '/conformance/results') {
			if (req.method !== 'POST') {
				res.statusCode = 405;
				res.end();
				return;
			}
			try {
				// https://nodejs.org/docs/latest-v20.x/api/stream.html#streampipelinesource-transforms-destination-options
				await mkdir(RESULTS_DIR, { recursive: true });
				await pipeline(
					req,
					createWriteStream(`${RESULTS_DIR}/${new Date().toISOString()}.json`),
				);
			} catch (err) {
				console.error(err);
				res.statusCode = 500;
				res.end();
			}
			res.statusCode = 201;
			res.end();
			return;
		}

		res.statusCode = 404;
		res.end();
	});

	server.on('clientError', (err, socket) => {
		socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
	});

	server.on('close', () => {
		console.log('server close');
	});

	server.listen(3000);

	return server;
}

function main() {
	if (process.argv.length < 3) {
		console.error('missing arguments: {serialDevice} {baudRate}');
		process.exit(1);
	}

	let server: ReturnType<typeof createFidoConformanceToolsServer> | null = null;
	let port: SerialPort | null = null;

	const serialDevice = process.argv[2];
	const baudRateRaw = process.argv[3];
	const baudRate = parseInt(baudRateRaw);

	if (!Number.isInteger(baudRate)) {
		console.error(`invalid baudRate '${baudRateRaw}'`);
		process.exit(1);
	}

	// https://serialport.io/docs/guide-usage
	port = new SerialPort({
		path: serialDevice,
		baudRate: baudRate,
	});

	const cleanup = () => {
		if (server !== null) {
			server.close();
			server = null;
		}

		if (port !== null) {
			port.close();
			port = null;
		}
	};

	port.on('close', () => {
		console.log('port close');
		cleanup();
	});

	port.on('error', (err) => {
		console.error('port error', err);
		process.exit(1);
	});

	port.on('open', () => {
		console.log('port open');

		if (port === null) {
			return;
		}

		port.pipe(process.stdout);

		process.stdin.setRawMode(true);
		process.stdin.on('data', (data) => {
			// lowercase letter 'x'
			if (data.length > 0 && data[0] === 0x78) {
				cleanup();
			}
		});
		process.stdin.pipe(port);

		server = createFidoConformanceToolsServer(port);
	});
}

main();
