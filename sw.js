// Service Worker — offline + кеш статики для скорости
// Меняй CACHE_VERSION чтобы выкатить новую версию
const CACHE_VERSION = 'crm-agenta-v20260619-3';

const STATIC = [
  './',
  './index.html',
  './manifest.json',
  './icon.png',
  './privacy.html',
  './404.html',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', e => {
  // сразу активируем новую версию (без ожидания закрытия всех вкладок)
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_VERSION).then(c => c.addAll(STATIC).catch(()=>{}))
  );
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    // чистим старые кеши
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE_VERSION).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  // НЕ кешируем POST/PUT/DELETE и не наши origin запросы (Supabase, Telegram и т.д.)
  if (request.method !== 'GET' || url.origin !== location.origin) {
    return; // отдаём на сетевой стек браузера как есть
  }

  // Для навигации (HTML) — network-first чтобы свежий код всегда подгружался
  if (request.mode === 'navigate' || request.destination === 'document') {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(request);
        const cache = await caches.open(CACHE_VERSION);
        cache.put(request, fresh.clone());
        return fresh;
      } catch {
        const cached = await caches.match(request);
        return cached || caches.match('./index.html');
      }
    })());
    return;
  }

  // Для остальной статики (иконки, manifest) — cache-first для мгновенной загрузки
  e.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) {
      // фоном обновляем
      fetch(request).then(r => {
        if (r && r.ok) caches.open(CACHE_VERSION).then(c => c.put(request, r));
      }).catch(()=>{});
      return cached;
    }
    try {
      const fresh = await fetch(request);
      if (fresh && fresh.ok) {
        const cache = await caches.open(CACHE_VERSION);
        cache.put(request, fresh.clone());
      }
      return fresh;
    } catch {
      return new Response('', { status: 504 });
    }
  })());
});
