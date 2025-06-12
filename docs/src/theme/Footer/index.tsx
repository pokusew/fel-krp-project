import React, { type ReactNode } from 'react';

import { ThemeClassNames } from '@docusaurus/theme-common';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import IconExternalLink from '@theme/Icon/ExternalLink';

function Footer(): ReactNode {
	return (
		<footer
			className={clsx(
				ThemeClassNames.layout.footer.container,
				'footer',
				'footer--dark',
			)}
		>
			<div className="container container-fluid text--center">
				<div className="footer__links">
					<Link
						className="footer__link-item"
						to="https://github.com/pokusew/lionkey"
					>
						View LionKey on GitHub <IconExternalLink />
					</Link>
				</div>
			</div>
			<div className="footer__bottom text--center">
				<div className="footer__copyright">
					Copyright © 2025{' '}
					<Link className="footer__link-item" to="https://github.com/pokusew">
						Martin Endler
					</Link>
				</div>
			</div>
		</footer>
	);
}

export default React.memo(Footer);
