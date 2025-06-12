import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';

// @ts-ignore
import logoUrl from '@site/assets/img/lionkey-logo-v2-no-padding.svg?file';

export default function NavbarLogo(): ReactNode {
	return (
		<Link to="/" className="navbar__brand">
			<div className="navbar__logo">
				<img alt="LionKey Logo" width="32" src={logoUrl} />
			</div>
		</Link>
	);
}
