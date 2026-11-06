// Unlock page for the private preview. Every real page, script and data file of the site is published encrypted
// (AES-256-GCM, key from the password via PBKDF2-SHA-256). This page derives the key from the password, checks it,
// keeps it in this browser (IndexedDB, not extractable), and installs a service worker (sw.js) that decrypts each
// file as the browser asks for it. It also derives the access key the site sends to the VibeInsights service.

const BASE = new URL("./", import.meta.url);
const $ = (id) => document.getElementById(id);
const say = (t) => ($("gate-msg").textContent = t);
const te = new TextEncoder();
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function idb() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("vibeinsights-site", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("keys");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}
async function saveKey(key) {
  const db = await idb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put(key, "site");
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function deriveKey(password, meta) {
  const material = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64(meta.salt), iterations: meta.iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function unlock(password) {
  const meta = await (await fetch(new URL("meta.json", BASE), { cache: "no-cache" })).json();
  const key = await deriveKey(password, meta);
  const blob = new Uint8Array(await (await fetch(new URL("enc/check.bin", BASE), { cache: "no-cache" })).arrayBuffer());
  try {
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12), additionalData: te.encode("check") }, key, blob.slice(12));
  } catch {
    return false;
  }
  await saveKey(key);
  try {
    localStorage.setItem("vibeinsights-access", b64url(await crypto.subtle.digest("SHA-256", te.encode(`vibeinsights-access:${password}`))));
  } catch {
    // Storage blocked: the pages open, but checks can't reach the service.
  }
  return true;
}

async function main() {
  if (!("serviceWorker" in navigator) || !window.indexedDB || !crypto?.subtle) {
    $("gate-form").hidden = true;
    return say("This browser can't open the private preview (it blocks service workers or storage — for example in some private windows). Try Chrome, Edge, Safari or Firefox in a normal window.");
  }
  let reg;
  try {
    reg = await navigator.serviceWorker.register(new URL("sw.js", BASE), { scope: BASE.pathname });
  } catch {
    $("gate-form").hidden = true;
    return say("This browser can't open the private preview (it doesn't allow the secure viewer, a service worker — common in in-app browsers). Open the link in Chrome, Edge, Safari or Firefox.");
  }
  // Unlocked already, but this tab isn't controlled yet (first load after unlocking): reload once.
  if (sessionStorage.getItem("vibeinsights-unlocked") === "1" && !navigator.serviceWorker.controller) {
    sessionStorage.removeItem("vibeinsights-unlocked");
    await navigator.serviceWorker.ready;
    return location.reload();
  }
  $("gate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $("gate-pw").value;
    if (!pw) return;
    $("gate-btn").disabled = true;
    say("Unlocking…");
    try {
      if (!(await unlock(pw))) {
        say("That password isn't right.");
        $("gate-btn").disabled = false;
        return;
      }
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) {
        await new Promise((resolve) => {
          navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
          reg.active?.postMessage({ type: "vibeinsights:claim" });
          setTimeout(resolve, 1500);
        });
      }
      sessionStorage.setItem("vibeinsights-unlocked", "1");
      location.reload();
    } catch {
      say("Couldn't unlock right now. Check your connection and try again.");
      $("gate-btn").disabled = false;
    }
  });
  $("gate-pw").focus();
}

main();
