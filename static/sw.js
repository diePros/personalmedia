// App-shell-only service worker. It caches the fixed list below at install and
// nothing else, ever: documents, previews, search results and every other
// authenticated response always go to the network (and are `no-store`).
"use strict";

const CACHE = "pm-shell-__ASSET_VERSION__";
const OFFLINE = "/static/offline.html";
const PRECACHE = [
  "/static/app.css",
  "/static/app.js",
  "/static/scan.css",
  "/static/scan.js",
  "/static/htmx.min.js",
  "/static/icons/icon.svg",
  "/static/icons/favicon.svg",
  "/static/icons/favicon-32.png",
  "/static/icons/favicon-16.png",
  "/static/icons/apple-touch-icon.png",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/icon-maskable-512.png",
  "/static/offline.html",
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (cache) {
      // `reload` bypasses the HTTP cache so the shell is never stale.
      return cache.addAll(
        PRECACHE.map(function (url) {
          return new Request(url, { cache: "reload" });
        }),
      );
    }),
  );
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches
      .keys()
      .then(function (names) {
        return Promise.all(
          names
            .filter(function (name) {
              return name.indexOf("pm-shell-") === 0 && name !== CACHE;
            })
            .map(function (name) {
              return caches.delete(name);
            }),
        );
      })
      .then(function () {
        return self.clients.claim();
      }),
  );
});

self.addEventListener("fetch", function (event) {
  const req = event.request;
  const url = new URL(req.url);

  // Only GETs are ever answered here. In particular the share target is a
  // top-level POST navigation (`mode === "navigate"`); it must go straight to
  // the network untouched, or the files would be lost.
  if (req.method !== "GET") {
    return;
  }

  // Shell assets: cache-first, same origin, GET only.
  if (
    url.origin === self.location.origin &&
    PRECACHE.indexOf(url.pathname) !== -1
  ) {
    event.respondWith(
      caches.match(url.pathname).then(function (hit) {
        return hit || fetch(req);
      }),
    );
    return;
  }

  // Pages: always the network; the offline notice only if it fails.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req).catch(function () {
        return caches.match(OFFLINE).then(function (r) {
          // Cache evicted or half-installed: a plain network error beats
          // respondWith(undefined).
          return r || Response.error();
        });
      }),
    );
  }
  // Everything else is left alone: no respondWith, no caching.
});
