"use strict";

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/unlock") await refresh();
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 1800);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied to clipboard");
  } catch {
    toast("Copy failed");
  }
}

// ---------- auth ----------

let initialized = false;

async function refresh() {
  const s = await api("GET", "/api/status");
  initialized = s.initialized;
  $("auth").hidden = s.unlocked;
  $("app").hidden = !s.unlocked;
  $("lock-btn").hidden = !s.unlocked;
  if (s.unlocked) {
    await Promise.all([loadEntries(), generate()]);
  } else {
    $("auth-title").textContent = initialized ? "Unlock vault" : "Create vault";
    $("auth-hint").textContent = initialized
      ? "Enter your master password to decrypt your vault."
      : "Choose a master password. It encrypts your vault and cannot be recovered if lost.";
    $("auth-submit").textContent = initialized ? "Unlock" : "Create vault";
    $("confirm-row").hidden = initialized;
    $("master2").required = !initialized;
    $("master").focus();
  }
}

$("auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("auth-error").textContent = "";
  const master = $("master").value;
  if (!initialized && master !== $("master2").value) {
    $("auth-error").textContent = "Passwords do not match.";
    return;
  }
  try {
    await api("POST", initialized ? "/api/unlock" : "/api/setup", { master });
    $("master").value = $("master2").value = "";
    await refresh();
  } catch (err) {
    $("auth-error").textContent = err.message;
  }
});

$("lock-btn").addEventListener("click", async () => {
  await api("POST", "/api/lock");
  $("gen-output").value = "";
  await refresh();
});

// ---------- generator ----------

function genOptions() {
  return {
    length: Number($("gen-length").value),
    lower: $("gen-lower").checked,
    upper: $("gen-upper").checked,
    digits: $("gen-digits").checked,
    symbols: $("gen-symbols").checked,
    excludeAmbiguous: $("gen-ambiguous").checked,
  };
}

async function generate() {
  $("gen-error").textContent = "";
  try {
    const r = await api("POST", "/api/generate", genOptions());
    $("gen-output").value = r.password;
    showStrength(r.entropyBits);
    return r.password;
  } catch (err) {
    $("gen-error").textContent = err.message;
    return null;
  }
}

function showStrength(bits) {
  let label = "Weak", color = "#f85149";
  if (bits >= 100) [label, color] = ["Excellent", "#2ea043"];
  else if (bits >= 75) [label, color] = ["Strong", "#3fb950"];
  else if (bits >= 50) [label, color] = ["Fair", "#d29922"];
  const bar = $("meter-bar");
  bar.style.width = Math.min(100, (bits / 128) * 100) + "%";
  bar.style.background = color;
  $("meter-text").textContent = `${label} · ${bits} bits of entropy`;
}

$("gen-length").addEventListener("input", () => {
  $("len-label").textContent = $("gen-length").value;
  generate();
});
for (const id of ["gen-lower", "gen-upper", "gen-digits", "gen-symbols", "gen-ambiguous"]) {
  $(id).addEventListener("change", generate);
}
$("gen-btn").addEventListener("click", generate);
$("gen-copy").addEventListener("click", () => $("gen-output").value && copy($("gen-output").value));
$("gen-save").addEventListener("click", () => openDialog(null, $("gen-output").value));

// ---------- vault ----------

let entries = [];

async function loadEntries() {
  entries = await api("GET", "/api/entries");
  renderEntries();
}

function renderEntries() {
  const q = $("search").value.trim().toLowerCase();
  const list = $("entries");
  list.replaceChildren();
  const shown = entries.filter((e) =>
    [e.name, e.username, e.url].some((f) => f.toLowerCase().includes(q)));
  $("empty").hidden = shown.length > 0;
  $("empty").textContent = entries.length ? "No matches." : "No entries yet.";

  for (const e of shown) {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.className = "info";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = e.name;
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = [e.username, e.url].filter(Boolean).join(" · ");
    info.append(name, sub);

    const actions = document.createElement("div");
    actions.className = "actions";
    actions.append(
      button("Copy", () => copy(e.password)),
      button("Edit", () => openDialog(e)),
      button("Delete", async () => {
        if (!confirm(`Delete "${e.name}"?`)) return;
        await api("DELETE", "/api/entries/" + encodeURIComponent(e.id));
        await loadEntries();
      }, "danger"),
    );
    li.append(info, actions);
    list.append(li);
  }
}

function button(text, onClick, extra = "") {
  const b = document.createElement("button");
  b.className = ("btn small " + extra).trim();
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

$("search").addEventListener("input", renderEntries);
$("add-btn").addEventListener("click", () => openDialog(null));

// ---------- entry dialog ----------

let editingId = null;

function openDialog(entry, password = "") {
  editingId = entry ? entry.id : null;
  $("dialog-title").textContent = entry ? "Edit entry" : "New entry";
  $("f-name").value = entry?.name ?? "";
  $("f-username").value = entry?.username ?? "";
  $("f-password").value = entry?.password ?? password;
  $("f-password").type = "password";
  $("f-show").textContent = "Show";
  $("f-url").value = entry?.url ?? "";
  $("f-notes").value = entry?.notes ?? "";
  $("entry-error").textContent = "";
  $("dialog").showModal();
  $("f-name").focus();
}

$("f-cancel").addEventListener("click", () => $("dialog").close());
$("f-show").addEventListener("click", () => {
  const f = $("f-password");
  f.type = f.type === "password" ? "text" : "password";
  $("f-show").textContent = f.type === "password" ? "Show" : "Hide";
});
$("f-gen").addEventListener("click", async () => {
  const pw = await generate();
  if (pw) $("f-password").value = pw;
});

$("entry-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = {
    name: $("f-name").value,
    username: $("f-username").value,
    password: $("f-password").value,
    url: $("f-url").value,
    notes: $("f-notes").value,
  };
  try {
    if (editingId) await api("PUT", "/api/entries/" + encodeURIComponent(editingId), body);
    else await api("POST", "/api/entries", body);
    $("dialog").close();
    await loadEntries();
    toast("Saved");
  } catch (err) {
    $("entry-error").textContent = err.message;
  }
});

refresh();
