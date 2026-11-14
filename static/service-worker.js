/* Cache only immutable app assets; never cache API responses or personalized pages. */
const CACHE = 'nexo-shell-v3';
const SHELL = ['/static/style.css','/static/app.js','/static/pwa.js','/static/icons/icon-192.png','/static/icons/icon-512.png'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith('nexo-shell-')&&k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET') return;
  const url=new URL(event.request.url);
  if(url.origin!==self.location.origin || url.pathname.startsWith('/api/') || url.pathname==='/' || url.pathname==='/manifest.webmanifest') return;
  if(!SHELL.includes(url.pathname)) return;
  event.respondWith(fetch(event.request).then(response=>{
    if(response.ok){const copy=response.clone();caches.open(CACHE).then(c=>c.put(event.request,copy));}
    return response;
  }).catch(()=>caches.match(event.request)));
});
