import { withLingo } from "@lingo.dev/compiler/next";

const LINGO_SOURCE_ROOT = "./src";
const LINGO_DIR = "../.lingo";
const LINGO_SOURCE_LOCALE = "en";
const LINGO_TARGET_LOCALES = ["fr", "es"];
const USE_PSEUDO_TRANSLATOR =
  process.env.LINGO_USE_PSEUDO_TRANSLATOR === "true" || !process.env.LINGODOTDEV_API_KEY;
const LINGO_COOKIE_CONFIG = {
  type: "cookie",
  config: {
    name: "locale",
    maxAge: 31_536_000,
  },
};

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/translations/:locale.json",
        destination: "/api/translations/:locale",
      },
    ];
  },
  webpack: (config) => {
    const translationServerUrl =
      process.env.LINGO_TRANSLATION_SERVER_URL ?? "http://127.0.0.1:60000";

    config.module ??= {};
    config.module.rules ??= [];

    // Workaround for Next 14 + Windows path separators where lingo virtual loaders are skipped.
    config.module.rules.unshift(
      {
        enforce: "pre",
        test: /virtual[\\/]config\.mjs$/i,
        use: [
          {
            loader: "@lingo.dev/compiler/next-config-loader",
            options: {
              sourceRoot: LINGO_SOURCE_ROOT,
              lingoDir: LINGO_DIR,
              sourceLocale: LINGO_SOURCE_LOCALE,
              dev: {
                usePseudotranslator: USE_PSEUDO_TRANSLATOR,
                translationServerUrl,
              },
            },
          },
        ],
      },
      {
        enforce: "pre",
        test: /virtual[\\/]locale[\\/]client\.mjs$/i,
        use: [
          {
            loader: "@lingo.dev/compiler/next-locale-client-loader",
            options: {
              sourceRoot: LINGO_SOURCE_ROOT,
              lingoDir: LINGO_DIR,
              sourceLocale: LINGO_SOURCE_LOCALE,
              localePersistence: LINGO_COOKIE_CONFIG,
            },
          },
        ],
      },
      {
        enforce: "pre",
        test: /virtual[\\/]locale[\\/]server\.mjs$/i,
        use: [
          {
            loader: "@lingo.dev/compiler/next-locale-server-loader",
            options: {
              sourceRoot: LINGO_SOURCE_ROOT,
              lingoDir: LINGO_DIR,
              sourceLocale: LINGO_SOURCE_LOCALE,
              localePersistence: LINGO_COOKIE_CONFIG,
            },
          },
        ],
      },
    );

    return config;
  },
};

export default async function () {
  return withLingo(nextConfig, {
    sourceRoot: LINGO_SOURCE_ROOT,
    lingoDir: LINGO_DIR,
    sourceLocale: LINGO_SOURCE_LOCALE,
    targetLocales: LINGO_TARGET_LOCALES,
    useDirective: true,
    localePersistence: LINGO_COOKIE_CONFIG,
    models: "lingo.dev",
    dev: {
      usePseudotranslator: USE_PSEUDO_TRANSLATOR,
    },
  });
}
