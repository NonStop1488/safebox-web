const CACHE = 'safebox-v2';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  // Тільки GET запити кешуємо
  if (e.request.method !== 'GET') return;
  
  const url = new URL(e.request.url);
  
  // API запити — завжди мережа
  if (url.hostname.includes('onrender.com')) return;
  
  // Тільки наші файли
  if (!url.hostname.includes('vercel.app') && 
      !url.hostname.includes('localhost')) return;

  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});