/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
export const $ = document.querySelector.bind(document);

export async function _fetch(path, payload = '') {
  const headers = {
    'X-Requested-With': 'XMLHttpRequest',
  };
  if (payload && !(payload instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw new Error(result.error);
  }
};

export const base64url = {
  encode: function(buffer) {
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  },
  decode: function(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binStr = window.atob(base64);
    const bin = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bin[i] = binStr.charCodeAt(i);
    }
    return bin.buffer;
  }
}

class Loading {
  constructor() {
    this.progress = $('#progress');
  }
  start() {
    this.progress.indeterminate = true;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = true);
    }
  }
  stop() {
    this.progress.indeterminate = false;
    const inputs = document.querySelectorAll('input');
    if (inputs) {
      inputs.forEach(input => input.disabled = false);
    }
  }
}

export const loading = new Loading();

// TODO: Add an ability to create a passkey: Create the registerCredential() function.
export async function registerCredential() {

  // TODO: Add an ability to create a passkey: Obtain the challenge and other options from the server endpoint.
  // const options = await _fetch('/auth/registerRequest');
  const options = await _fetch('/auth/request-credential-create-options');

  // TODO: Add an ability to create a passkey: Create a credential.
  // Base64URL decode some values.
  options.user.id = base64url.decode(options.user.id);
  options.challenge = base64url.decode(options.challenge);

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
    }
  }
  
  // Use platform authenticator and discoverable credential.
  options.authenticatorSelection = {
    authenticatorAttachment: 'platform',
    requireResidentKey: true
  }
  
  // Invoke the WebAuthn create() method.
  const cred = await navigator.credentials.create({
    publicKey: options,
  });

  // TODO: Add an ability to create a passkey: Register the credential to the server endpoint.
  const credential = {};
  credential.id = cred.id;
  credential.rawId = cred.id; // Pass a Base64URL encoded ID string.
  credential.type = cred.type;

  // The authenticatorAttachment string in the PublicKeyCredential object is a new addition in WebAuthn L3.
  if (cred.authenticatorAttachment) {
    credential.authenticatorAttachment = cred.authenticatorAttachment;
  }

  // Base64URL encode some values.
  const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
  const attestationObject = base64url.encode(cred.response.attestationObject);

  // Obtain transports.
  const transports = cred.response.getTransports ? cred.response.getTransports() : [];

  credential.response = {
    clientDataJSON,
    attestationObject,
    transports
  };
  
  return await _fetch('/auth/register-created-credentials', credential);
};

// TODO: Add an ability to authenticate with a passkey: Create the authenticate() function.

export async function updateCredential(credId, newName) {
  return _fetch(`/auth/renameKey`, { credId, newName });
}

export async function unregisterCredential(credId) {
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};