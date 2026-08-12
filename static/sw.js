/*
 * Casey service worker.
 *
 * Strategy (deliberately conservative — Casey is an authenticated journal):
 *   - Static assets (/static/ and Google Fonts): cache-first. They carry no
 *     user data and are safe to keep on-device.
 *   - Navigations (HTML): network-only, falling back to the offline page when
 *     the network is unreachable. Page content is per-user and must never be
 *     served from cache.
 *   - Everything else (API calls, form posts): untouched — straight to the
 *     network, never cached.
 *
 * CACHE_VERSION must be bumped on every release (see CLAUDE.md ship workflow)
 * so installed clients drop stale assets on activate.
 */

const CACHE_VERSION = 'casey-sw-1';
const STATIC_CACHE = CACHE_VERSION + '-static';
const OFFLINE_URL = '/static/offline.html';

const PRECACHE = [
    OFFLINE_URL,
    '/static/favicon.svg',
    '/static/icon-192.png',
    '/static/icon-512.png',
    '/static/manifest.json'
];

const FONT_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => cache.addAll(PRECACHE))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(
                keys
                    .filter((key) => key.startsWith('casey-') && key !== STATIC_CACHE)
                    .map((key) => caches.delete(key))
            ))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const request = event.request;

    // Never touch anything but GET — form posts, API writes etc. go straight
    // through to the network.
    if (request.method !== 'GET') return;

    const url = new URL(request.url);

    // Navigations: network-only. Authenticated HTML is never cached; when the
    // network is gone, show the offline page instead of a browser error.
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request).catch(() => caches.match(OFFLINE_URL))
        );
        return;
    }

    // Static assets and fonts: cache-first, populate on first fetch.
    const isOwnStatic = url.origin === self.location.origin && url.pathname.startsWith('/static/');
    const isFont = FONT_HOSTS.includes(url.hostname);

    if (isOwnStatic || isFont) {
        event.respondWith(
            caches.match(request).then((cached) => {
                if (cached) return cached;
                return fetch(request).then((response) => {
                    if (response.ok || response.type === 'opaque') {
                        const copy = response.clone();
                        caches.open(STATIC_CACHE).then((cache) => cache.put(request, copy));
                    }
                    return response;
                });
            })
        );
    }

    // Anything else (e.g. /api/*): default browser behaviour, no caching.
});
