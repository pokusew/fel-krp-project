import React, { type ReactNode } from 'react';
import clsx from 'clsx';
import type { Props } from '@theme/NotFound/Content';
import Heading from '@theme/Heading';
import Link from '@docusaurus/Link';

export default function NotFoundContent({ className }: Props): ReactNode {
	return (
		<main className={clsx('container margin-vert--xl', className)}>
			<div className="row">
				<div className="col col--6 col--offset-3">
					<Heading as="h1" className="hero__title">
						Page Not Found
					</Heading>
					<p>Check the URL or try using the navigation bar.</p>
					<Link className="button button--secondary button--lg" to="/">
						Go to homepage
					</Link>
				</div>
			</div>
		</main>
	);
}
