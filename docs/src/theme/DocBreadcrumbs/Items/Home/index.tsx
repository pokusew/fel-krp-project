import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import IconHome from '@theme/Icon/Home';

import styles from './styles.module.css';

export default function HomeBreadcrumbItem(): ReactNode {
	const homeHref = useBaseUrl('/docs');

	return (
		<li className="breadcrumbs__item">
			<Link
				aria-label="Documentation Root Page"
				className="breadcrumbs__link"
				href={homeHref}
			>
				<IconHome className={styles.breadcrumbHomeIcon} />
			</Link>
		</li>
	);
}
