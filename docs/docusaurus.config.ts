import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import path from 'node:path';

// useful when debugging the webpack config
// import util from 'node:util';
// util.inspect.defaultOptions.depth = Infinity;

// https://docusaurus.io/docs/api/docusaurus-config
const config: Config = {
	// https://docusaurus.io/docs/api/docusaurus-config#required-fields
	title: 'LionKey',
	url: 'https://lionkey.dev',
	baseUrl: '/',

	// https://docusaurus.io/docs/api/docusaurus-config#trailingSlash
	// https://developers.cloudflare.com/workers/static-assets/routing/advanced/html-handling/
	trailingSlash: false,

	titleDelimiter: '|',

	// favicon: 'img/favicon.ico',

	// Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
	future: {
		v4: true, // Improve compatibility with the upcoming Docusaurus v4
	},

	onBrokenLinks: 'throw',
	onBrokenAnchors: 'warn',
	onBrokenMarkdownLinks: 'warn',

	baseUrlIssueBanner: false,

	i18n: {
		defaultLocale: 'en',
		locales: ['en'],
	},

	presets: [
		[
			'classic',
			{
				pages: {
					path: './src/pages/',
					routeBasePath: '/',
				},
				blog: false,
				docs: {
					path: './content/',
					routeBasePath: 'docs',
					sidebarPath: './src/sidebars.ts',
					editUrl: 'https://github.com/pokusew/lionkey/tree/main/docs/',
				},
				theme: {
					customCss: './src/css/custom.css',
				},
			} satisfies Preset.Options,
		],
	],

	themeConfig: {
		// image: 'img/lionkey-social-card.jpg',
		navbar: {
			hideOnScroll: true,
			title: 'LionKey',
			items: [
				{
					type: 'docSidebar',
					sidebarId: 'docsSidebar',
					position: 'left',
					label: 'Docs',
				},
				{
					href: 'https://github.com/pokusew/lionkey',
					label: 'GitHub',
					position: 'right',
				},
			],
		},
		prism: {
			theme: prismThemes.github,
			darkTheme: prismThemes.dracula,
		},
	} satisfies Preset.ThemeConfig,

	plugins: [
		() => ({
			name: 'lionkey-webpack',
			// https://docusaurus.io/docs/api/plugin-methods/lifecycle-apis#configureWebpack
			configureWebpack(config, isServer, utils, content) {
				// console.log(
				// 	`lionkey-webpack isServer = ${isServer}, rules =`,
				// 	config.module.rules,
				// );
				return {
					mergeStrategy: { 'module.rules': 'replace' },
					module: {
						rules: config.module.rules.map((rule) => {
							if (typeof rule !== 'object' || rule === null) {
								return rule;
							}

							if (
								rule.test instanceof RegExp &&
								rule.test.toString() === '/\\.svg$/i'
							) {
								if (!Array.isArray(rule.oneOf)) {
									throw new Error();
								}
								const customAssetsDir = path.resolve(__dirname, 'assets');
								return {
									...rule,
									oneOf: [
										{
											resourceQuery: '?file',
											test: /\.svg$/,
											include: [customAssetsDir],
											use: [
												{
													loader: 'file-loader',
													options: {
														context: customAssetsDir,
														// the [path] is relative to the context
														name: 'assets/[path][name].[contenthash].[ext]',
														emitFile: !isServer,
													},
												},
											],
										},
										// default Docusaurus SVG inlining logic
										...rule.oneOf,
									],
								};
							}

							return rule;
						}),
					},
				};
			},
		}),
	],
};

export default config;
