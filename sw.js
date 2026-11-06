// Private preview: decrypts the site's files as the browser asks for them. Each file is published as
// enc/<path>.bin = 12-byte IV + AES-256-GCM ciphertext (the path is the additional data, so files can't be swapped).
// The key was derived from the password by the unlock page (gate.js) and stored in IndexedDB; without it, the
// published files are served as they are — which for every page is the unlock page.

const BASE = new URL("./", self.location).pathname;
const PLAIN = new Set(["gate.js", "gate.css", "sw.js", "meta.json", "robots.txt", ".nojekyll"]);
const TYPES = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  pdf: "application/pdf",
  txt: "text/plain; charset=utf-8",
};
const te = new TextEncoder();
let key = null;

function idb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("vibeinsights-site", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}
async function storedKey() {
  if (key) return key;
  try {
    const db = await idb();
    key = await new Promise((resolve) => {
      const req = db.transaction("keys").objectStore("keys").get("site");
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => resolve(null);
    });
  } catch {
    key = null;
  }
  return key;
}
async function forgetKey() {
  key = null;
  try {
    const db = await idb();
    db.transaction("keys", "readwrite").objectStore("keys").delete("site");
  } catch {
    // Nothing stored.
  }
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => {
  if (e.data?.type === "vibeinsights:lock") forgetKey();
  if (e.data?.type === "vibeinsights:claim") self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== self.location.origin || !url.pathname.startsWith(BASE)) return;
  let rel = decodeURIComponent(url.pathname.slice(BASE.length));
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  if (PLAIN.has(rel) || rel.startsWith("enc/") || rel.startsWith("fixtures/")) return;
  e.respondWith(serve(e.request, rel));
});

async function serve(request, rel) {
  const k = await storedKey();
  if (!k) return fetch(request);
  const res = await fetch(`${BASE}enc/${rel}.bin`, { cache: "no-cache" });
  if (!res.ok) return fetch(request);
  const blob = new Uint8Array(await res.arrayBuffer());
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12), additionalData: te.encode(rel) }, k, blob.slice(12));
    const ext = rel.split(".").pop().toLowerCase();
    return new Response(plain, { headers: { "content-type": TYPES[ext] ?? "application/octet-stream", "cache-control": "no-store" } });
  } catch {
    // The site was re-published with another password: forget the old key and show the unlock page.
    await forgetKey();
    return fetch(request);
  }
}
