
// Script adapted from https://unpkg.com/@tidal-music/auth/dist

import 'localstorage-polyfill';

import fetch from 'node-fetch';

globalThis.fetch = fetch;



console.log("hi ", globalThis.localStorage);

var u = Object.defineProperty;
var n = (s2, t, r2) => t in s2 ? u(s2, t, { enumerable: true, configurable: true, writable: true, value: r2 }) : s2[t] = r2;
var p = (s2, t, r2) => (n(s2, typeof t != "symbol" ? t + "" : t, r2), r2);
class e extends Error {
  /**
   * Constructor.
   *
   * @param errorCode Defined by the user of this error, but must match the regexp: [0-9a-z]{1,5}
   */
  constructor(r2, i2) {
    super(r2, i2);
    p(this, "errorCode");
    Object.setPrototypeOf(this, e.prototype), Error.captureStackTrace && Error.captureStackTrace(this, e), this.name = "TidalError", this.errorCode = r2;
  }
}
let c$1 = class c extends e {
  constructor(t, r2) {
    super(t, r2), Object.setPrototypeOf(this, c.prototype), Error.captureStackTrace && Error.captureStackTrace(this, c), this.name = "IllegalArgumentError";
  }
};
let a$1 = class a extends e {
  constructor(t, r2) {
    super(t, r2), Object.setPrototypeOf(this, a.prototype), Error.captureStackTrace && Error.captureStackTrace(this, a), this.name = "NetworkError";
  }
};
class o extends e {
  constructor(t, r2) {
    super(t, r2), Object.setPrototypeOf(this, o.prototype), Error.captureStackTrace && Error.captureStackTrace(this, o), this.name = "RetryableError";
  }
}
const d = {
  credentialsUpdated: "CredentialsUpdatedMessage"
};
var w = (n2, e2, t) => {
  if (!e2.has(n2))
    throw TypeError("Cannot " + t);
};
var r = (n2, e2, t) => (w(n2, e2, "read from private field"), t ? t.call(n2) : e2.get(n2)), h = (n2, e2, t) => {
  if (e2.has(n2))
    throw TypeError("Cannot add the same private member more than once");
  e2 instanceof WeakSet ? e2.add(n2) : e2.set(n2, t);
}, c2 = (n2, e2, t, o2) => (w(n2, e2, "write to private field"), o2 ? o2.call(n2, t) : e2.set(n2, t), t);
var i, a2, s;
class f {
  constructor(e2) {
    h(this, i, void 0);
    h(this, a2, void 0);
    h(this, s, void 0);
    c2(this, s, new URL(e2));
  }
  /**
   * Returns the current time adjusted to server-time.
   *
   * @param clientCurrentTime The current time on the client side. Defaults to Date.now().
   * @returns The current adjusted time.
   * @throws {ReferenceError} If the initialization has not been done yet. You need to call and await the `synchronize` method once.
   */
  // eslint-disable-next-line no-restricted-syntax
  now(e2 = Date.now()) {
    if (!r(this, a2) || !r(this, i))
      throw new ReferenceError(
        "Initialization has not been done yet. You need to call and await the synchronize method once."
      );
    return r(this, a2) + (e2 - r(this, i));
  }
  /**
   * Synchronizes the client's time with the server's time.
   * If the client's time is already synchronized within an hour, this method does nothing.
   *
   * @returns {Promise<void>} A promise that resolves when the synchronization is complete.
   */
  async synchronize() {
    if (!(r(this, i) && // eslint-disable-next-line no-restricted-syntax
    Math.abs(Date.now() - r(this, i)) < 36e5))
      try {
        const t = await fetch(r(this, s));
        t.ok && t.headers.has("date") && (c2(this, a2, new Date(t.headers.get("date")).getTime()), c2(this, i, Date.now()));
      } catch (t) {
        console.error(t);
      }
  }
  /**
   * Returns the timestamp of a performance mark with the specified name and detail.
   * PS: `performance.mark` must be called with `startTime: trueTime.now()`.
   *
   * @param markName - The name of the performance mark.
   * @param detail - Optional. The detail of the performance mark.
   * @returns The timestamp of the performance mark, or undefined if not found.
   * @throws ReferenceError if initialization has not been done yet or if the performance mark is not found.
   */
  timestamp(e2, t) {
    let o2;
    if (!r(this, a2) || !r(this, i))
      throw new ReferenceError(
        "Initialization has not been done yet. You need to call and await the synchronize method once."
      );
    if (t) {
      if (o2 = performance.getEntriesByName(e2).find((d2) => "detail" in d2 && d2.detail === t), !o2)
        throw new ReferenceError(
          `There is no performance entry named "${e2}" with detail "${t}"`
        );
    } else
      o2 = performance.getEntriesByName(e2).pop();
    return o2 ? o2.startTime : void 0;
  }
}
i = /* @__PURE__ */ new WeakMap(), a2 = /* @__PURE__ */ new WeakMap(), s = /* @__PURE__ */ new WeakMap();
const m = new f("https://api.tidal.com/v1/ping");
class AuthenticationError extends e {
  constructor(errorCode, options) {
    super(errorCode, options);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthenticationError);
    }
    this.name = "AuthenticationError";
  }
}
class TokenResponseError extends e {
  constructor(errorCode, options) {
    super(errorCode, options);
    Object.setPrototypeOf(this, TokenResponseError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenResponseError);
    }
    this.name = "TokenResponseError";
  }
}
class UnexpectedError extends e {
  constructor(errorCode, options) {
    super(errorCode, options);
    Object.setPrototypeOf(this, UnexpectedError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnexpectedError);
    }
    this.name = "UnexpectedError";
  }
}
const authErrorCodeMap = {
  authenticationError: "A0000",
  illegalArgumentError: "A0007",
  initError: "A0001",
  networkError: "A0002",
  retryableError: "A0003",
  storageError: "A0004",
  tokenResponseError: "A0005",
  unexpectedError: "A0006"
};
const prefix = "AuthDB";
function bufferToString(buf) {
  return String.fromCharCode(...new Uint8Array(buf));
}
function stringToUint8Array(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i2 = 0, strLen = str.length; i2 < strLen; i2++) {
    bufView[i2] = str.charCodeAt(i2);
  }
  return bufView;
}
const database = {
  getItem: (key) => {
    const result = globalThis.localStorage.getItem(`${prefix}/${key}`);
    return result ? stringToUint8Array(result) : void 0;
  },
  removeItem: (key) => {
    globalThis.localStorage.removeItem(`${prefix}/${key}`);
  },
  setItem: (key, data) => {
    globalThis.localStorage.setItem(`${prefix}/${key}`, bufferToString(data));
  }
};
const getKeyMaterial = (password) => {
  const enc = new TextEncoder();
  return globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
};
const getWrappingKey = (keyMaterial, salt) => {
  return globalThis.crypto.subtle.deriveKey(
    {
      hash: "SHA-256",
      iterations: 1e5,
      name: "PBKDF2",
      salt
    },
    keyMaterial,
    { length: 256, name: "AES-KW" },
    true,
    ["wrapKey", "unwrapKey"]
  );
};
const getUnwrappingKey = async (salt, password) => {
  const keyMaterial = await getKeyMaterial(password);
  return getWrappingKey(keyMaterial, salt);
};
const encodeCredentials = (credentials) => {
  const textEnc = new TextEncoder();
  return textEnc.encode(credentials);
};
const decodeCredentials = (credentials) => {
  const textEnc = new TextDecoder();
  return textEnc.decode(credentials);
};
const wrapCryptoKey = async ({
  keyToWrap,
  password,
  salt
}) => {
  const keyMaterial = await getKeyMaterial(password);
  const wrappingKey = await getWrappingKey(keyMaterial, salt);
  return globalThis.crypto.subtle.wrapKey(
    "raw",
    keyToWrap,
    wrappingKey,
    "AES-KW"
  );
};
const unwrapCryptoKey = async ({
  password,
  salt,
  wrappedKeyBuffer
}) => {
  const unwrappingKey = await getUnwrappingKey(salt, password);
  return globalThis.crypto.subtle.unwrapKey(
    "raw",
    wrappedKeyBuffer,
    unwrappingKey,
    "AES-KW",
    "AES-CTR",
    true,
    ["encrypt", "decrypt"]
  );
};
const encryptCredentials = ({
  content,
  counter,
  key
}) => {
  return globalThis.crypto.subtle.encrypt(
    { counter, length: 64, name: "AES-CTR" },
    key,
    content
  );
};
const decryptCredentials = ({
  counter,
  encryptedCredentials,
  key
}) => {
  return globalThis.crypto.subtle.decrypt(
    { counter, length: 64, name: "AES-CTR" },
    key,
    encryptedCredentials
  );
};
const getEncryptionKey = () => {
  return globalThis.crypto.subtle.generateKey(
    {
      length: 256,
      name: "AES-CTR"
    },
    true,
    ["encrypt", "decrypt"]
  );
};
const handleNewCryptoKey = async ({
  password,
  storageKey
}) => {
  const key = await getEncryptionKey();
  const counter = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const wrappedKey = await wrapCryptoKey({ keyToWrap: key, password, salt });
  try {
    database.setItem(`${storageKey}Counter`, counter);
    database.setItem(`${storageKey}Salt`, salt);
    database.setItem(`${storageKey}Key`, wrappedKey);
  } catch (error) {
    throw new e(authErrorCodeMap.storageError, {
      cause: error
    });
  }
};
const getStorageItems = (credentialsStorageKey) => {
  return {
    counter: database.getItem(`${credentialsStorageKey}Counter`),
    encryptedCredentials: database.getItem(
      `${credentialsStorageKey}Data`
    ),
    salt: database.getItem(`${credentialsStorageKey}Salt`),
    wrappedKey: database.getItem(`${credentialsStorageKey}Key`)
  };
};
const loadCredentials = async (credentialsStorageKey) => {
  const { counter, encryptedCredentials, salt, wrappedKey } = getStorageItems(
    credentialsStorageKey
  );
  if (encryptedCredentials && counter && wrappedKey && salt) {
    try {
      const secretKey = await unwrapCryptoKey({
        password: credentialsStorageKey,
        salt,
        wrappedKeyBuffer: wrappedKey
      });
      const credentials = await decryptCredentials({
        counter,
        encryptedCredentials,
        key: secretKey
      });
      return JSON.parse(decodeCredentials(credentials));
    } catch (error) {
      throw new e(authErrorCodeMap.storageError);
    }
  } else {
    return handleNewCryptoKey({
      password: credentialsStorageKey,
      storageKey: credentialsStorageKey
    });
  }
};
const saveCredentialsToStorage = async (credentials) => {
  const currentCredentials = await loadCredentials(
    credentials.credentialsStorageKey
  );
  const mergedCredentials = { ...currentCredentials, ...credentials };
  const { counter, salt, wrappedKey } = getStorageItems(
    credentials.credentialsStorageKey
  );
  if (!wrappedKey || !counter || !salt) {
    throw new e(authErrorCodeMap.storageError);
  }
  try {
    const secretKey = await unwrapCryptoKey({
      password: mergedCredentials.credentialsStorageKey,
      salt,
      wrappedKeyBuffer: wrappedKey
    });
    const encryptedCredentials = await encryptCredentials({
      content: encodeCredentials(JSON.stringify(mergedCredentials)),
      counter,
      key: secretKey
    });
    database.setItem(
      `${mergedCredentials.credentialsStorageKey}Data`,
      encryptedCredentials
    );
  } catch (error) {
    throw new e(authErrorCodeMap.storageError, {
      cause: error
    });
  }
};
const deleteCredentials = (credentialsStorageKey) => {
  database.removeItem(`${credentialsStorageKey}Data`);
  database.removeItem(`${credentialsStorageKey}Counter`);
  database.removeItem(`${credentialsStorageKey}Salt`);
  database.removeItem(`${credentialsStorageKey}Key`);
};
const handleErrorResponse = async (response) => {
  if (response.status === 0) {
    return new a$1(authErrorCodeMap.networkError);
  }
  if (response.status >= 400 && response.status < 500) {
    return new UnexpectedError(authErrorCodeMap.unexpectedError);
  }
  if (response.status >= 500 && response.status < 600) {
    return new o(authErrorCodeMap.retryableError);
  }
  const { error } = await response.json();
  return new TokenResponseError(authErrorCodeMap.tokenResponseError, {
    cause: error
  });
};
const handleTokenFetch = async ({
  body,
  credentials
}) => {
  const { options, url } = prepareFetch({
    body,
    credentials,
    path: "oauth2/token"
  });
  const response = await exponentialBackoff({
    request: () => globalThis.fetch(url, options),
    // only retry in certain error cases
    retry: (res) => res.status >= 500 && res.status < 600
  });
  if (!response.ok) {
    return await handleErrorResponse(response);
  }
  return response;
};
const prepareFetch = ({
  body,
  credentials,
  path
}) => {
  const url = `${credentials.tidalAuthServiceBaseUri}${path}`;
  const options = {
    body: new URLSearchParams(body).toString(),
    headers: {
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    },
    method: "POST"
  };
  return { options, url };
};
const exponentialBackoff = async ({
  delayInMs = 500,
  request,
  retry
}) => {
  let base = 1;
  const limitReached = () => base > 32;
  while (!limitReached()) {
    await new Promise((resolve) => setTimeout(resolve, base * delayInMs));
    const result = await request();
    base *= 2;
    const shouldRetry = retry(result);
    if (!shouldRetry || limitReached()) {
      return result;
    }
  }
  throw new UnexpectedError(authErrorCodeMap.unexpectedError);
};
const sha256 = async (message) => {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", msgUint8);
  const bytes = new Uint8Array(hashBuffer);
  const len = bytes.byteLength;
  let binary = "";
  for (let i2 = 0; i2 < len; i2 += 1) {
    binary += String.fromCharCode(bytes[i2]);
  }
  return globalThis.btoa(binary);
};
const base64URLEncode = (value) => value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
const generateOAuthCodeChallenge = () => {
  const array = new Uint8Array(100);
  const string = base64URLEncode(
    btoa(globalThis.crypto.getRandomValues(array).toString())
  );
  return string.slice(0, 128);
};
const state = {
  pending: false,
  pendingPromises: []
};
const TIDAL_LOGIN_SERVICE_BASE_URI = "https://login.tidal.com/";
const TIDAL_AUTH_SERVICE_BASE_URI = "https://auth.tidal.com/v1/";
const knownSubStatus = ["11003", "6001", "11001", "11002", "11101"];
const bus = (callbackFn) => {
  return globalThis.addEventListener(
    "authEventBus",
    callbackFn
  );
};
const dispatchEvent = (detail) => {
  const event = new CustomEvent("authEventBus", {
    detail
  });
  // Leaving this out for NodeJS implementation.
  //globalThis.dispatchEvent(event);
};
const dispatchCredentialsUpdated = (credentials) => {
  dispatchEvent({
    payload: credentials,
    type: d.credentialsUpdated
  });
};
const init = async ({
  clientId,
  clientSecret,
  clientUniqueKey,
  credentialsStorageKey,
  scopes,
  tidalAuthServiceBaseUri,
  tidalLoginServiceBaseUri
}) => {
  const persistedCredentials = await loadCredentials(credentialsStorageKey);
  const credentials = {
    ...persistedCredentials,
    clientId,
    ...clientSecret && {
      clientSecret
    },
    clientUniqueKey,
    credentialsStorageKey,
    // we store the clientSecret separately to determine if a token needs to be upgraded
    previousClientSecret: persistedCredentials == null ? void 0 : persistedCredentials.clientSecret,
    scopes: scopes ?? [],
    tidalAuthServiceBaseUri: tidalAuthServiceBaseUri ?? (persistedCredentials == null ? void 0 : persistedCredentials.tidalAuthServiceBaseUri) ?? TIDAL_AUTH_SERVICE_BASE_URI,
    tidalLoginServiceBaseUri: tidalLoginServiceBaseUri ?? (persistedCredentials == null ? void 0 : persistedCredentials.tidalLoginServiceBaseUri) ?? TIDAL_LOGIN_SERVICE_BASE_URI
  };
  await persistCredentials(credentials);
  await m.synchronize();
};
const initializeLogin = async ({
  loginConfig,
  redirectUri
}) => {
  if (!state.credentials) {
    throw new e(authErrorCodeMap.initError);
  }
  const codeChallenge = generateOAuthCodeChallenge();
  const codeChallengeSha256 = await sha256(codeChallenge);
  await persistCredentials({
    ...state.credentials,
    codeChallenge,
    redirectUri
  });
  const queryData = {
    // don't let custom params overwrite internals
    ...loginConfig,
    client_id: state.credentials.clientId,
    ...state.credentials.clientUniqueKey && {
      client_unique_key: state.credentials.clientUniqueKey
    },
    code_challenge: base64URLEncode(codeChallengeSha256),
    code_challenge_method: "S256",
    redirect_uri: redirectUri,
    response_type: "code",
    scope: state.credentials.scopes.join(" ")
  };
  const queryParameters = new URLSearchParams(queryData).toString();
  return { authorizeUrl: `${state.credentials.tidalLoginServiceBaseUri}authorize?${queryParameters}`, codeChallenge };
};
const initializeDeviceLogin = async () => {
  if (!state.credentials) {
    throw new e(authErrorCodeMap.initError);
  }
  const body = {
    client_id: state.credentials.clientId,
    ...state.credentials.clientSecret && {
      client_secret: state.credentials.clientSecret
    },
    scope: state.credentials.scopes.join(" ")
  };
  const { options, url } = prepareFetch({
    body,
    credentials: state.credentials,
    path: "oauth2/device_authorization"
  });
  const response = await exponentialBackoff({
    request: () => globalThis.fetch(url, options),
    // only retry in certain error cases
    retry: (res) => res.status >= 500 && res.status < 600
  });
  if (!response.ok) {
    throw await handleErrorResponse(response);
  }
  const jsonResponse = await response.json();
  state.limitedDeviceResponse = jsonResponse;
  return jsonResponse;
};
const finalizeLogin = async (loginResponseQuery) => {
  var _a, _b, _c;
  if (!((_a = state.credentials) == null ? void 0 : _a.credentialsStorageKey) || !((_b = state.credentials) == null ? void 0 : _b.codeChallenge) || !((_c = state.credentials) == null ? void 0 : _c.redirectUri)) {
    throw new e(authErrorCodeMap.initError);
  }
  const {
    clientId,
    clientSecret,
    clientUniqueKey,
    codeChallenge,
    redirectUri,
    scopes
  } = state.credentials;
  const params = Object.fromEntries(new URLSearchParams(loginResponseQuery));
  if (!params.code) {
    throw new AuthenticationError(authErrorCodeMap.authenticationError);
  }
  const body = {
    client_id: clientId,
    client_unique_key: clientUniqueKey ?? "",
    ...clientSecret && {
      client_secret: clientSecret
    },
    code: params.code,
    code_verifier: codeChallenge,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
    scope: scopes.join(" ")
  };
  const response = await handleTokenFetch({
    body,
    credentials: state.credentials
  });
  if (response instanceof Error) {
    throw response;
  }
  const jsonResponse = await response.json();
  await persistToken(jsonResponse);
  return;
};
const finalizeDeviceLogin = async () => {
  if (!state.credentials || !state.limitedDeviceResponse) {
    throw new e(authErrorCodeMap.initError);
  }
  const { clientId, clientSecret, clientUniqueKey, scopes } = state.credentials;
  const { deviceCode, expiresIn, interval } = state.limitedDeviceResponse;
  const body = {
    client_id: clientId,
    ...clientSecret && {
      client_secret: clientSecret
    },
    client_unique_key: clientUniqueKey ?? "",
    device_code: deviceCode,
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    scope: scopes.join(" ")
  };
  const { options, url } = prepareFetch({
    body,
    credentials: state.credentials,
    path: "oauth2/token"
  });
  const expiresTimestamp = new Date(
    m.now() + expiresIn * 1e3
  ).getTime();
  const limitReached = () => expiresTimestamp < m.now();
  while (!limitReached()) {
    await new Promise((resolve) => setTimeout(resolve, interval * 1e3));
    const response = await globalThis.fetch(url, options);
    if (response.ok) {
      const jsonResponse = await response.json();
      await persistToken(jsonResponse);
      return;
    }
    if (response.status >= 500 && response.status < 600) {
      const retriedResponse = await exponentialBackoff({
        request: () => globalThis.fetch(url, options),
        // only retry in certain error cases
        retry: (res) => res.status >= 500 && res.status < 600
      });
      if (retriedResponse.ok) {
        const jsonResponse = await retriedResponse.json();
        await persistToken(jsonResponse);
        return;
      }
      if (retriedResponse.status >= 500 && retriedResponse.status < 600) {
        throw await handleErrorResponse(retriedResponse);
      }
    }
    if (limitReached()) {
      throw new TokenResponseError(authErrorCodeMap.tokenResponseError, {
        cause: "Request limit reached"
      });
    }
  }
};
const logout = () => {
  var _a;
  dispatchEvent({ type: d.credentialsUpdated });
  if ((_a = state.credentials) == null ? void 0 : _a.credentialsStorageKey) {
    deleteCredentials(state.credentials.credentialsStorageKey);
  }
  delete state.credentials;
  delete state.limitedDeviceResponse;
};
const refreshAccessToken = async () => {
  var _a;
  if ((_a = state.credentials) == null ? void 0 : _a.refreshToken) {
    const body = {
      ...state.credentials.clientSecret && {
        client_secret: state.credentials.clientSecret
      },
      client_id: state.credentials.clientId,
      grant_type: "refresh_token",
      refresh_token: state.credentials.refreshToken,
      scope: state.credentials.scopes.join(" ")
    };
    const response = await handleTokenFetch({
      body,
      credentials: state.credentials
    });
    if (response instanceof Error) {
      return response;
    }
    const jsonResponse = await response.json();
    return persistToken(jsonResponse);
  } else {
    return getTokenThroughClientCredentials();
  }
};
const upgradeToken = async () => {
  var _a;
  if ((_a = state.credentials) == null ? void 0 : _a.refreshToken) {
    const body = {
      ...state.credentials.clientSecret && {
        client_secret: state.credentials.clientSecret
      },
      client_id: state.credentials.clientId,
      grant_type: "update_client",
      refresh_token: state.credentials.refreshToken,
      scope: state.credentials.scopes.join(" ")
    };
    const { options, url } = prepareFetch({
      body,
      credentials: state.credentials,
      path: "oauth2/token"
    });
    const response = await exponentialBackoff({
      request: () => globalThis.fetch(url, options),
      // only retry in certain error cases
      retry: (res) => res.status >= 400 && res.status < 600
    });
    if (!response.ok) {
      if (response.status === 0) {
        throw new a$1(authErrorCodeMap.networkError);
      }
      throw new o(authErrorCodeMap.retryableError);
    }
    const jsonResponse = await response.json();
    return persistToken(jsonResponse);
  } else {
    return getTokenThroughClientCredentials();
  }
};
const getTokenThroughClientCredentials = async () => {
  var _a;
  if ((_a = state.credentials) == null ? void 0 : _a.clientSecret) {
    const body = {
      client_id: state.credentials.clientId,
      client_secret: state.credentials.clientSecret,
      grant_type: "client_credentials",
      scope: state.credentials.scopes.join(" ")
    };
    const response = await handleTokenFetch({
      body,
      credentials: state.credentials
    });
    if (response instanceof Error) {
      return response;
    }
    const jsonResponse = await response.json();
    return persistToken(jsonResponse);
  }
};
const getCredentials = async (apiErrorSubStatus) => {
  if (state.pending) {
    await new Promise((resolve) => {
      state.pendingPromises.push(resolve);
    });
  }
  return getCredentialsInternal(apiErrorSubStatus).finally(() => {
    const resolve = state.pendingPromises.shift();
    if (resolve) {
      resolve();
    }
    state.pending = false;
  });
};
const getCredentialsInternal = async (apiErrorSubStatus) => {
  if (state.credentials) {
    state.pending = true;
    const { accessToken } = state.credentials;
    const oneMinute = 60 * 1e3;
    if (accessToken) {
      const newScopeIsSameOrSubset = state.credentials.scopes.every(
        (scope) => {
          var _a;
          return (_a = accessToken.grantedScopes) == null ? void 0 : _a.includes(scope);
        }
      );
      if (state.credentials.clientUniqueKey !== accessToken.clientUniqueKey || newScopeIsSameOrSubset === false) {
        logout();
        throw new c$1(authErrorCodeMap.illegalArgumentError);
      }
      const shouldUpgradeToken = state.credentials.clientId !== (accessToken == null ? void 0 : accessToken.clientId) || state.credentials.previousClientSecret !== state.credentials.clientSecret;
      if (shouldUpgradeToken) {
        const upgradeTokenResponse = await upgradeToken();
        if (upgradeTokenResponse && "token" in upgradeTokenResponse) {
          return upgradeTokenResponse;
        } else {
          throw new o(authErrorCodeMap.retryableError);
        }
      }
      const shouldRefresh = Boolean(
        apiErrorSubStatus && knownSubStatus.includes(apiErrorSubStatus)
      );
      if (!shouldRefresh && accessToken.expires && accessToken.expires > m.now() + oneMinute) {
        return accessToken;
      }
      const accessTokenResponse = await refreshAccessToken();
      if (accessTokenResponse && "token" in accessTokenResponse) {
        return accessTokenResponse;
      }
      if (accessTokenResponse instanceof UnexpectedError) {
        logout();
        throw accessTokenResponse;
      }
      if (accessTokenResponse instanceof o) {
        throw accessTokenResponse;
      }
    } else if (state.credentials.clientSecret) {
      const accessTokenResponse = await getTokenThroughClientCredentials();
      if (accessTokenResponse && "token" in accessTokenResponse) {
        return accessTokenResponse;
      } else if (accessTokenResponse instanceof Error) {
        throw accessTokenResponse;
      }
    } else {
      return {
        clientId: state.credentials.clientId,
        requestedScopes: state.credentials.scopes
      };
    }
  }
  throw new e(authErrorCodeMap.initError);
};
const setCredentials = async ({
  accessToken,
  refreshToken
}) => {
  if (!state.credentials) {
    throw new e(authErrorCodeMap.initError);
  }
  const newScopeIsSubset = state.credentials.scopes.every(
    (scope) => {
      var _a;
      return (_a = accessToken.grantedScopes) == null ? void 0 : _a.includes(scope);
    }
  );
  if (state.credentials.clientUniqueKey !== accessToken.clientUniqueKey || state.credentials.clientId !== accessToken.clientId || newScopeIsSubset === false || !accessToken.expires || !accessToken.token) {
    throw new c$1(authErrorCodeMap.illegalArgumentError);
  }
  await persistCredentials({
    ...state.credentials,
    accessToken,
    ...refreshToken && {
      refreshToken
    }
  });
};
const persistCredentials = (updatedCredentials) => {
  state.credentials = updatedCredentials;
  const credentials = {
    ...state.credentials.accessToken,
    clientId: state.credentials.clientId,
    requestedScopes: state.credentials.scopes
  };
  dispatchCredentialsUpdated(credentials);
  return saveCredentialsToStorage(state.credentials);
};
const persistToken = async (jsonResponse) => {
  var _a, _b;
  if (!state.credentials) {
    throw new e(authErrorCodeMap.initError);
  }
  const { clientId, clientUniqueKey, scopes } = state.credentials;
  const grantedScopes = ((_a = jsonResponse.scope) == null ? void 0 : _a.length) ? (_b = jsonResponse.scope) == null ? void 0 : _b.split(" ") : [];
  const accessToken = {
    clientId,
    clientUniqueKey,
    // `expires_in` is sent in seconds, needs transformation to milliseconds
    expires: m.now() + jsonResponse.expires_in * 1e3,
    grantedScopes,
    requestedScopes: scopes,
    token: jsonResponse.access_token,
    ...jsonResponse.user_id && {
      userId: jsonResponse.user_id.toString()
    }
  };
  await persistCredentials({
    ...state.credentials,
    accessToken,
    // there is no refreshToken when renewing the accessToken
    ...jsonResponse.refresh_token && {
      refreshToken: jsonResponse.refresh_token
    }
  });
  return accessToken;
};
const credentialsProvider = {
  bus,
  getCredentials
};
export {
  authErrorCodeMap,
  credentialsProvider,
  finalizeDeviceLogin,
  finalizeLogin,
  init,
  initializeDeviceLogin,
  initializeLogin,
  logout,
  setCredentials
};
//# sourceMappingURL=index.js.map

