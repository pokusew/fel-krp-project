import type { ReactNode } from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import Heading from '@theme/Heading';

import styles from './index.module.css';
import Head from '@docusaurus/Head';
// @ts-ignore
import logoUrl from '@site/assets/img/lionkey-logo-v2-no-padding.svg?file';

function HomepageHeader() {
	return (
		<header className={clsx('hero hero--primary', styles.heroBanner)}>
			<div className="container">
				<img alt="LionKey Logo" className={styles.logo} src={logoUrl} />
				<Heading as="h1" className="hero__title">
					LionKey
				</Heading>
				<p className="hero__subtitle">
					An open-source FIDO2 USB Security Key 🔑 implemented on STM32H533.
					<br />
					CTAP 2.1 compliant. Supports passkeys.
				</p>
				<div className={styles.buttons}>
					<Link className="button button--secondary button--lg" to="/docs">
						Documentation
					</Link>
					<Link
						className="button button--secondary button--lg"
						to="https://github.com/pokusew/lionkey"
					>
						View on GitHub
					</Link>
				</div>
			</div>
		</header>
	);
}

export default function Home(): ReactNode {
	return (
		<Layout description="LionKey is an open-source FIDO2 USB Security Key 🔑 implemented on STM32H533. It is CTAP 2.1 compliant and supports passkeys. It is easily portable and can be used as a library.">
			{/* @ts-ignore */}
			<Head title={'LionKey: An Open-Source FIDO2 USB Security Key'} />

			<HomepageHeader />

			<main>
				<HomepageFeatures />
			</main>
		</Layout>
	);
}
