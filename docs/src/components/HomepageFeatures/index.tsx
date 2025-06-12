import type { ReactNode } from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
	title: string;
	description: ReactNode;
};

const FeatureList: FeatureItem[] = [
	{
		title: 'WebAuthn authenticator',
		description: (
			<>
				<strong>LionKey</strong> is a roaming authenticator with{' '}
				<em>cross-platform attachment</em> using CTAP 2.1 over USB 2.0 (CTAPHID)
				as the communication protocol, supporting <em>user verification</em> using
				PIN (CTAP2 ClientPIN), and capable of storing <strong>passkeys</strong> (
				<em>client-side discoverable credentials</em>).
			</>
		),
	},
	{
		title: 'Usable as a library',
		description: (
			<>
				LionKey provides a <strong>fully compliant</strong> implementation of CTAP
				2.1 with all mandatory features. It is written in <strong>C</strong>,
				without dynamic memory allocations, designed for use in
				resource-constrained environments. The core parts are MCU independent,
				easily portable, and can be used as a&nbsp;library.
			</>
		),
	},
	{
		title: 'Easily portable',
		description: (
			<>
				The reference implementation is fully usable security key that runs on the
				NUCLEO-H533RE board, featuring the <strong>STM32H533</strong> MCU and
				hardware-accelerated cryptography.
				<br />
				It can be easily ported to different MCUs.
			</>
		),
	},
];

function Feature({ title, description }: FeatureItem) {
	return (
		<div className={clsx('col col--4')}>
			<div className="text--center padding-horiz--md">
				<Heading as="h3">{title}</Heading>
				<p>{description}</p>
			</div>
		</div>
	);
}

export default function HomepageFeatures(): ReactNode {
	return (
		<section className={styles.features}>
			<div className="container">
				<div className="row">
					{FeatureList.map((props, idx) => (
						<Feature key={idx} {...props} />
					))}
				</div>
			</div>
		</section>
	);
}
