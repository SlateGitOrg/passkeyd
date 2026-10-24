// passkeyd demo client: plain browser JavaScript, no framework, no build.
// It converts between the server's WebAuthn Level 3 JSON options/responses
// and the browser's ArrayBuffer-based navigator.credentials API.
"use strict";

const b64urlToBuf = (s) => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};

const bufToB64url = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// Fallbacks for browsers without parse*OptionsFromJSON / toJSON.
function creationOptionsFromJSON(o) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) {
    return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  }
  return {
    ...o,
    challenge: b64urlToBuf(o.challenge),
    user: { ...o.user, id: b64urlToBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
}

function requestOptionsFromJSON(o) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  }
  return {
    ...o,
    challenge: b64urlToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
}

function credentialToJSON(cred) {
  if (typeof cred.toJSON === "function") return cred.toJSON();
  const r = cred.response;
  const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bufToB64url(r.attestationObject);
    response.transports = r.getTransports ? r.getTransports() : [];
  } else {
    response.authenticatorData = bufToB64url(r.authenticatorData);
    response.signature = bufToB64url(r.signature);
    if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    const err = new Error(data.message || res.statusText);
    err.code = data.error;
    throw err;
  }
  return data;
}

function log(title, ok, detail) {
  const li = document.createElement("li");
  const strong = document.createElement("strong");
  strong.className = ok ? "ok" : "bad";
  strong.textContent = title;
  li.appendChild(strong);
  if (detail !== undefined) {
    const pre = document.createElement("pre");
    pre.textContent = typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
    li.appendChild(pre);
  }
  document.getElementById("log").prepend(li);
}

async function withButton(form, fn) {
  const btn = form.querySelector("button");
  btn.disabled = true;
  try {
    await fn();
  } catch (e) {
    log(e.code ? `Rejected: ${e.code}` : `Error: ${e.name}`, false, e.message);
  } finally {
    btn.disabled = false;
  }
}

async function register(form) {
  const username = form.username.value.trim();
  const displayName = form.displayName.value.trim();
  const options = await api("/api/register/options", { username, displayName });
  const cred = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(options) });
  const result = await api("/api/register/verify", credentialToJSON(cred));
  log(`Registered ${result.username}`, true, result);
}

async function login(form) {
  const username = form.username.value.trim();
  const options = await api("/api/login/options", { username });
  const cred = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(options) });
  const result = await api("/api/login/verify", credentialToJSON(cred));
  log(`Signed in as ${result.username}`, !result.cloneWarning, result);
}

document.addEventListener("DOMContentLoaded", () => {
  const support = document.getElementById("support");
  if (!window.PublicKeyCredential) {
    support.textContent = "This browser does not support WebAuthn.";
    return;
  }
  support.textContent = window.isSecureContext
    ? "WebAuthn is available in this browser."
    : "WebAuthn needs a secure context: use https or http://localhost.";
  const regForm = document.getElementById("register-form");
  const loginForm = document.getElementById("login-form");
  regForm.addEventListener("submit", (e) => {
    e.preventDefault();
    withButton(regForm, () => register(regForm));
  });
  loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    withButton(loginForm, () => login(loginForm));
  });
});
