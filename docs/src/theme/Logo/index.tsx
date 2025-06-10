import React, { type ReactNode } from 'react';
import Link from '@docusaurus/Link';
import type { Props } from '@theme/Logo';

// @ts-ignore
import logoUrl from '@site/assets/img/lionkey-logo-v2-no-padding.svg?file';

export default function Logo(props: Props): ReactNode {
	const { imageClassName, titleClassName, ...propsRest } = props;

	return (
		<Link to="/" {...propsRest}>
			<img className={imageClassName} alt="LionKey Logo" width="32" src={logoUrl} />
			<b className={titleClassName}>LionKey</b>
		</Link>
	);
}
