import { strFromU8, unzipSync } from 'fflate';
import type { AnisetteData, AppleAPI, AppID, Certificate, Device, Team } from 'altsign.js';
import { initLibcurl } from './anisette-libcurl-init';
import { requireLibcurl } from './wasm/libcurl';

const SIGNING_IDENTITY_STORAGE_KEY = 'webmuxd:signing-identities';
const PRIMARY_APP_INFO_PLIST_RE = /^Payload\/[^/]+\.app\/Info\.plist$/;

interface ParsedIpaInfo {
  bundleId?: string;
  displayName?: string;
}

interface CachedSigningIdentityPayload {
  certId: string;
  certPublicKeyBase64: string;
  privateKeyBase64: string;
}

interface StoredSigningIdentityMap {
  [appleAndTeamKey: string]: CachedSigningIdentityPayload;
}

export interface AppleSigningCredentials {
  appleId: string;
  password: string;
}

export interface AppleSigningRequest {
  ipaFile: File;
  anisetteData: AnisetteData;
  credentials: AppleSigningCredentials;
  deviceUdid: string;
  deviceName?: string;
  bundleIdOverride?: string;
  displayNameOverride?: string;
  onLog: (message: string) => void;
}

export interface AppleSigningResult {
  signedFile: File;
  outputBundleId: string;
  teamId: string;
}

export interface AppleDeveloperSession {
  anisetteData: AnisetteData;
  dsid: string;
  authToken: string;
}

export interface AppleDeveloperContext {
  appleId: string;
  session: AppleDeveloperSession;
  team: Team;
  certificates: Certificate[];
  devices: Device[];
}

export interface TrustedPhoneNumber {
  id: number;
  numberWithDialCode: string;
  obfuscatedNumber: string;
  pushMode: string;
}

export interface TwoFactorContext {
  /** Submit a 6-digit code that was pushed to a trusted device. */
  submitDeviceCode: (code: string) => void;
  /** Available trusted phone numbers for SMS fallback. Empty when none. */
  trustedPhoneNumbers: TrustedPhoneNumber[];
  /** Request an SMS be sent to the given phone id, then call submitSmsCode. */
  requestSms: (phoneId: number) => Promise<void>;
  /** Submit the code received via SMS for the given phone id. */
  submitSmsCode: (phoneId: number, code: string) => Promise<void>;
}

export interface AppleDeveloperLoginRequest {
  anisetteData: AnisetteData;
  credentials: AppleSigningCredentials;
  onLog?: (message: string) => void;
  onTwoFactorRequired?: (ctx: TwoFactorContext) => void;
}

export interface AppleSigningWithContextRequest {
  ipaFile: File;
  context: AppleDeveloperContext;
  deviceUdid: string;
  deviceName?: string;
  bundleIdOverride?: string;
  displayNameOverride?: string;
  onLog: (message: string) => void;
}

interface AltsignModule {
  AppleAPI: new (fetch: unknown) => AppleAPI;
  Fetch: new (
    initLibcurl: typeof import('./anisette-libcurl-init').initLibcurl,
    fetcher: (
      url: string,
      options: {
        method?: string;
        headers?: HeadersInit;
        body?: BodyInit | null;
      },
    ) => Promise<Response>,
  ) => unknown;
  signIPA(options: {
    ipaData?: Uint8Array;
    ipaPath?: string;
    outputPath?: string;
    certificate: Uint8Array;
    privateKey: Uint8Array;
    provisioningProfile: Uint8Array;
    bundleID?: string;
    displayName?: string;
    adhoc?: boolean;
    forceSign?: boolean;
  }): Promise<{ data: Uint8Array }>;
}

/** Minimal type alias for the Fetch instance used in the SMS patch. */
type AltsignFetch = {
  get(url: string, headers?: Record<string, string>): Promise<{ text(): Promise<string>; ok: boolean }>;
  request(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<{ text(): Promise<string>; ok: boolean }>;
};

let altsignModulePromise: Promise<AltsignModule> | null = null;
/** Cached fetch wrapper — the libcurl WASM underneath is expensive to re-init. */
let appleFetchInstance: AltsignFetch | null = null;

// ---------- Apple GSA SMS 2FA endpoints ----------

const GSA_TRUSTED_DEVICE_URL = 'https://gsa.apple.com/auth/verify/trusteddevice';
const GSA_VALIDATE_URL = 'https://gsa.apple.com/grandslam/GsService2/validate';
/** Request an SMS be sent to a phone number (PUT, no `/put` suffix). */
const GSA_PHONE_URL = 'https://gsa.apple.com/auth/verify/phone';
const GSA_PHONE_CODE_URL = 'https://gsa.apple.com/auth/verify/phone/securitycode';

/** Replace the private handleTwoFactor method on the auth sub-object so we get
 *  the trusted-phone list and can drive SMS verification from the UI. */
function patchHandleTwoFactor(api: AppleAPI, fetch: AltsignFetch): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const auth: any = (api as any).auth;
  if (!auth || typeof auth.handleTwoFactor !== 'function') return;

  auth.handleTwoFactor = async function (
    dsid: string,
    idmsToken: string,
    anisetteData: AnisetteData,
    verificationHandler: ((ctx: TwoFactorContext) => void) | undefined,
  ): Promise<boolean> {
    if (!verificationHandler) return false;
    try {
      const identityToken = btoa(`${dsid}:${idmsToken}`);
      const headers: Record<string, string> = {
        'Content-Type': 'text/x-xml-plist',
        'User-Agent': 'Xcode',
        Accept: 'text/x-xml-plist',
        'Accept-Language': 'en-us',
        'X-Apple-App-Info': 'com.apple.gs.xcode.auth',
        'X-Xcode-Version': '11.2 (11B41)',
        'X-Apple-Identity-Token': identityToken,
        'X-Apple-I-MD-M': anisetteData.machineID,
        'X-Apple-I-MD': anisetteData.oneTimePassword,
        'X-Apple-I-MD-LU': anisetteData.localUserID,
        'X-Apple-I-MD-RINFO': String(anisetteData.routingInfo),
        'X-Mme-Device-Id': anisetteData.deviceUniqueIdentifier,
        'X-MMe-Client-Info': anisetteData.deviceDescription,
        'X-Apple-I-Client-Time': auth.formatDate(anisetteData.date),
        'X-Apple-Locale': anisetteData.locale,
        'X-Apple-I-TimeZone': anisetteData.timeZone,
      };

      // Trigger push to trusted devices AND get trusted phone numbers.
      let trustedPhoneNumbers: TrustedPhoneNumber[] = [];
      try {
        const deviceResp = await fetch.get(GSA_TRUSTED_DEVICE_URL, headers);
        const deviceText = await deviceResp.text();
        trustedPhoneNumbers = parseTrustedPhones(deviceText);
        console.log('[2FA] parsed trustedPhoneNumbers:', trustedPhoneNumbers);
        if (trustedPhoneNumbers.length === 0) {
          // Log key fragments to diagnose the response format
          const snippets = [
            deviceText.match(/"trustedPhoneNumbers"\s*:\s*(\[[\s\S]{0,300}?\])/)?.[1],
            deviceText.match(/phoneNumbers[\s\S]{0,200}/)?.[0],
            // Apple auth HTML embeds data in various script tags
            deviceText.match(/window\.AUTH_INIT_DATA\s*=\s*({[\s\S]{0,400}?});/)?.[1],
            deviceText.match(/var\s+bootstrap\s*=\s*({[\s\S]{0,400}?});/)?.[1],
            deviceText.match(/<script[^>]*id="boot_args"[^>]*>([\s\S]{0,400}?)<\/script>/i)?.[1],
            deviceText.match(/<script[^>]*type="text\/x-apple-plist"[^>]*>([\s\S]{0,400}?)<\/script>/i)?.[1],
            deviceText.match(/<script[^>]*type="application\/json"[^>]*>([\s\S]{0,400}?)<\/script>/i)?.[1],
          ].filter(Boolean);
          console.log('[2FA] phone fragments:', snippets);
        }
      } catch (e) {
        console.warn('[2FA] trusteddevice request failed (non-fatal):', e);
      }

      return await new Promise<boolean>((resolve) => {
        const jsonHeaders = {
          ...headers,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        };

        const submitDeviceCode = async (code: string) => {
          const trimmed = code.trim();
          // '__CANCELLED__' sentinel: user dismissed the modal — skip network request.
          if (!trimmed || trimmed === '__CANCELLED__') { resolve(false); return; }
          try {
            const verifyHeaders = { ...headers, 'security-code': trimmed };
            const resp = await fetch.get(GSA_VALIDATE_URL, verifyHeaders);
            const text = await resp.text();
            const plist = parsePlistSimple(text);
            resolve((plist as Record<string, unknown>)['ec'] === 0);
          } catch { resolve(false); }
        };

        const requestSms = async (phoneId: number): Promise<void> => {
          const body = JSON.stringify({ phoneNumber: { id: phoneId }, mode: 'sms' });
          console.log('[2FA] requestSms → PUT', GSA_PHONE_URL, 'phoneId:', phoneId);
          const resp = await fetch.request('PUT', GSA_PHONE_URL, jsonHeaders, body);
          const respText = await resp.text();
          console.log('[2FA] requestSms response ok:', resp.ok, 'body:', respText.slice(0, 200));
          if (!resp.ok) throw new Error(`Failed to send SMS (${respText.slice(0, 100)})`);
        };

        const submitSmsCode = async (phoneId: number, code: string): Promise<void> => {
          const body = JSON.stringify({
            phoneNumber: { id: phoneId },
            securityCode: { code: code.trim() },
            mode: 'sms',
          });
          const resp = await fetch.request('POST', GSA_PHONE_CODE_URL, jsonHeaders, body);
          const text = await resp.text();
          console.log('[2FA] submitSmsCode response ok:', resp.ok, 'body:', text.slice(0, 200));
          let ok = resp.ok;
          try {
            const parsed = JSON.parse(text) as Record<string, unknown>;
            if (parsed['ec'] !== undefined) ok = parsed['ec'] === 0;
          } catch { /* plist fallback */ }
          if (!ok) throw new Error('SMS verification failed');
          // SMS 2FA is complete — resolve(true) so altsign.js retries authenticate()
          // with fresh anisette (handled by patchAuthenticateRetry).
          resolve(true);
        };

        try {
          verificationHandler({ submitDeviceCode, trustedPhoneNumbers, requestSms, submitSmsCode });
        } catch { resolve(false); }
      });
    } catch {
      return false;
    }
  };
}

/** patchAuthenticateRetry: on the post-2FA re-call, swap in a fresh anisette OTP
 *  so the SRP exchange doesn't crash on a stale one-time password.
 *
 *  patchSendAuthRequest: Apple may return au:"secondaryAuth" instead of
 *  au:"trustedDeviceSecondaryAuth" for accounts without a trusted device (SMS-only
 *  2FA). altsign.js only checks for the latter, so it silently falls through to
 *  fetchAuthToken which then crashes with atob(undefined). We normalize the value
 *  so altsign.js's existing 2FA path fires correctly.
 *
 *  For accounts where Apple signals 2FA ONLY at the apptokens stage (no au in the
 *  SRP complete response), we intercept the empty apptokens response, trigger 2FA,
 *  then throw a sentinel so the authenticate wrapper performs a full fresh SRP
 *  exchange (Apple invalidates the SRP session after 2FA at this stage). */
const REAUTH_SENTINEL = '__SIDEIMPACTOR_NEEDS_FULL_REAUTH__';

function patchAuthenticateRetry(api: AppleAPI, _apiFetch: AltsignFetch): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const auth: any = (api as any).auth;
  if (!auth || typeof auth.authenticate !== 'function') return;

  // Store the verificationHandler from the current authenticate() call so the
  // sendAuthRequest patch can forward it to handleTwoFactor when needed.
  let storedVerificationHandler: ((ctx: TwoFactorContext) => void) | undefined;
  // After 2FA completes, mark it done so we don't re-trigger if the second
  // apptokens attempt also returns empty (shouldn't happen, but guards loops).
  let twoFactorDone = false;

  // --- patch sendAuthRequest ---
  if (typeof auth.sendAuthRequest === 'function') {
    const origSend: (...a: unknown[]) => Promise<Record<string, unknown>> =
      auth.sendAuthRequest.bind(auth);
    auth.sendAuthRequest = async function (...args: unknown[]): Promise<Record<string, unknown>> {
      const params = args[0] as Record<string, unknown>;
      const anisetteArg = args[1] as AnisetteData;

      // Wrap origSend so we can intercept apptokens 2FA signals.
      // Apple uses two different conventions to signal "2FA required at apptokens":
      //   (a) Older: returns a non-plist / empty body → parsePlist yields {} (no Status)
      //   (b) Newer: returns ec=-22421 "This action could not be completed. Try again."
      //       which altsign.js converts into a thrown Error before returning to us.
      // We catch case (b) here and fall through to the shared 2FA-gate logic below.
      let response: Record<string, unknown>;
      try {
        response = await origSend(...args);
      } catch (e) {
        const isApptokens = params?.['o'] === 'apptokens';
        const is22421 = e instanceof Error && e.message.includes('(-22421)');
        if (isApptokens && is22421 && !twoFactorDone) {
          console.log('[auth] apptokens threw -22421 — treating as 2FA gate (Apple new-style signal)');
          response = {}; // fall through to 2FA handling below
        } else {
          throw e;
        }
      }

      const status = response['Status'] as Record<string, unknown> | undefined;
      const au = status?.['au'];
      console.log('[auth] sendAuthRequest o=%s au=%s keys=%o', params?.['o'], au, Object.keys(response));

      // Normalize legacy au value
      if (au === 'secondaryAuth') {
        console.log('[auth] normalizing au: secondaryAuth → trustedDeviceSecondaryAuth');
        (status as Record<string, unknown>)['au'] = 'trustedDeviceSecondaryAuth';
        return response;
      }

      // Detect 2FA required at apptokens stage.
      // Covers both empty response (case a) and the -22421 catch above (case b).
      if (params?.['o'] === 'apptokens' && Object.keys(response).length === 0) {
        if (twoFactorDone) {
          // 2FA was already completed — this is a genuine failure, not a gate.
          throw new Error('Authentication failed after two-factor verification. Please sign in again.');
        }
        console.log('[auth] apptokens 2FA gate detected — triggering verification');
        const adsid = params['u'] as string;
        const idmsToken = params['t'] as string;
        if (adsid && idmsToken && storedVerificationHandler) {
          const success = await auth.handleTwoFactor(
            adsid, idmsToken, anisetteArg, storedVerificationHandler,
          );
          if (success) {
            // Apple invalidates the SRP session after 2FA at this stage.
            // Throw a sentinel so loginAppleDeveloperAccount starts a fresh SRP exchange.
            console.log('[auth] 2FA done — signalling full re-authentication');
            twoFactorDone = true;
            throw new Error(REAUTH_SENTINEL);
          }
        }
        // 2FA was cancelled by the user or no handler was available.
        // Throw instead of returning {} so altsign.js doesn't try to process
        // an invalid empty response (which would crash with atob(undefined)).
        throw new Error('Two-factor authentication was cancelled. Please sign in again.');
      }

      return response;
    };
  } else {
    console.warn('[auth] sendAuthRequest not found on auth — patch skipped');
  }

  // --- patch authenticate ---
  // Responsibilities:
  //   1. Capture verificationHandler so sendAuthRequest can pass it to handleTwoFactor.
  //   2. On post-2FA retry (callCount > 1), swap in fresh anisette.
  //   3. If REAUTH_SENTINEL is thrown from the apptokens path, re-throw it unchanged
  //      so loginAppleDeveloperAccount can catch it and do a clean fresh login with a
  //      new AppleAPI instance (avoids state-pollution in the current auth object).
  const original: (...args: unknown[]) => Promise<unknown> = auth.authenticate.bind(auth);
  let callCount = 0;

  auth.authenticate = async function (...args: unknown[]): Promise<unknown> {
    callCount++;
    storedVerificationHandler = args[3] as ((ctx: TwoFactorContext) => void) | undefined;
    console.log(`[auth] authenticate call #${callCount}`);

    // Always use fresh anisette on any retry call (callCount > 1).
    if (callCount > 1) {
      try {
        const { getAnisetteData } = await import('./anisette-service');
        const freshAnisette = await getAnisetteData();
        args = [...args];
        args[2] = freshAnisette;
        console.log('[auth] post-2FA retry: swapped in fresh anisette OTP');
      } catch (e) {
        console.warn('[auth] post-2FA retry: could not fetch fresh anisette, proceeding with original', e);
      }
    }

    try {
      return await original(...args);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // Bubble the sentinel unchanged — loginAppleDeveloperAccount handles it
      // by creating a fresh AppleAPI instance for a clean re-auth.
      if (msg === REAUTH_SENTINEL) {
        throw e;
      }
      console.error(`[auth] authenticate call #${callCount} threw:`, e);
      throw e;
    }
  };
}

/** Extract `ec` from an Apple GSA response (JSON or XML plist). */
function parsePlistSimple(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try { return JSON.parse(trimmed); } catch { /* fall through */ }
  }
  // XML plist — reuse the file's own parser
  return parseXmlPlist(trimmed);
}

function parseTrustedPhones(text: string): TrustedPhoneNumber[] {
  const trimmed = text.trim();

  // Path 1: plain JSON response  { "trustedPhoneNumbers": [...] }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(trimmed) as Record<string, unknown>;
      const phones = data['trustedPhoneNumbers'];
      if (Array.isArray(phones)) return mapPhones(phones as Record<string, unknown>[]);
    } catch { /* fall through */ }
  }

  // Path 2: Apple Auth HTML — phone numbers are in
  //   <script type="application/json" class="boot_args">{ "direct": { "trustedDeviceVerification": { "phoneNumberVerification": { "trustedPhoneNumbers": [...] } } } }</script>
  const bootArgsMatch = trimmed.match(
    /<script[^>]+class="boot_args"[^>]*>([\s\S]*?)<\/script>/i,
  );
  if (bootArgsMatch) {
    try {
      const boot = JSON.parse(bootArgsMatch[1]) as Record<string, unknown>;
      const tdv = (boot['direct'] as Record<string, unknown> | undefined)?.['trustedDeviceVerification'] as Record<string, unknown> | undefined;
      const pnv = tdv?.['phoneNumberVerification'] as Record<string, unknown> | undefined;
      const phones = pnv?.['trustedPhoneNumbers'];
      if (Array.isArray(phones)) return mapPhones(phones as Record<string, unknown>[]);
    } catch { /* fall through */ }
  }

  // Path 3: XML plist (older Apple endpoints)
  if (trimmed.startsWith('<?xml') || trimmed.startsWith('<plist')) {
    const data = parseXmlPlist(trimmed);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const phones = (data as Record<string, unknown>)['trustedPhoneNumbers'];
      if (Array.isArray(phones)) return mapPhones(phones as Record<string, unknown>[]);
    }
  }

  return [];
}

function mapPhones(raw: Record<string, unknown>[]): TrustedPhoneNumber[] {
  return raw.map((p) => ({
    id: typeof p['id'] === 'number' ? p['id'] : Number(p['id']),
    numberWithDialCode: typeof p['numberWithDialCode'] === 'string' ? p['numberWithDialCode'] : '',
    obfuscatedNumber: typeof p['obfuscatedNumber'] === 'string' ? p['obfuscatedNumber'] : '',
    pushMode: typeof p['pushMode'] === 'string' ? p['pushMode'] : 'sms',
  }));
}

/**
 * Keep `altsign.js` and its transitive `zsign-wasm` bundle out of the initial
 * Vite module graph. They are only needed after the user starts login/signing.
 */
async function loadAltsignModule(): Promise<AltsignModule> {
  if (!altsignModulePromise) {
    altsignModulePromise = import('altsign.js').then((moduleValue) => {
      return moduleValue as unknown as AltsignModule;
    });
  }
  return await altsignModulePromise;
}

async function getAppleApi(log?: (msg: string) => void): Promise<{ api: AppleAPI; fetch: AltsignFetch }> {
  const uiLog = log ?? (() => undefined);
  const { AppleAPI, Fetch } = await loadAltsignModule();
  if (!appleFetchInstance) {
    const doFetch = async (url: string, options: {
      method?: string;
      headers?: HeadersInit;
      body?: BodyInit | null;
    }): Promise<Response> => {
      const libcurl = requireLibcurl();
      const libcurlOpts = {
        method: options.method,
        headers: options.headers,
        body: options.body,
        redirect: 'manual',
        insecure: true,
        verbose: 4,
        _libcurl_http_version: 1.1,
      } as never;
      let response = await libcurl.fetch(url, libcurlOpts) as Response;
      // Auto-retry on Apple GSA 503 (transient rate-limit / overload).
      // Use exponential backoff: 5s, 10s, 20s, 40s — up to ~75s total.
      if (url.includes('gsa.apple.com') && response.status === 503) {
        const delays = [5000, 10000, 20000, 40000];
        for (let attempt = 0; attempt < delays.length; attempt++) {
          const waitSec = delays[attempt] / 1000;
          const msg = `login: Apple server busy (503) — retrying in ${waitSec}s (${attempt + 1}/${delays.length})...`;
          console.warn(`[fetch] ${msg}`);
          uiLog(msg);
          await new Promise((r) => setTimeout(r, delays[attempt]));
          response = await libcurl.fetch(url, libcurlOpts) as Response;
          if (response.status !== 503) break;
        }
        if (response.status === 503) {
          throw new Error('Apple authentication server is temporarily unavailable (503). Please wait a few minutes and try again.');
        }
      }
      // Log raw response body for Apple auth endpoint calls (diagnosis aid).
      if (url.includes('gsa.apple.com')) {
        const origText = response.text.bind(response);
        response.text = async () => {
          const text = await origText();
          console.log('[fetch] raw text from %s status=%d (%d chars): %s',
            url.split('?')[0], response.status, text.length, text.slice(0, 300));
          return text;
        };
      }
      return response;
    };
    const f = new Fetch(initLibcurl, doFetch);
    appleFetchInstance = f as AltsignFetch;
  }
  // Always create a fresh AppleAPI per call — it holds no expensive state,
  // but reusing it across separate authenticate() calls causes -22421 because
  // the anisette OTP embedded in the previous call is already consumed.
  const api = new AppleAPI(appleFetchInstance);
  patchHandleTwoFactor(api, appleFetchInstance);
  patchAuthenticateRetry(api, appleFetchInstance);
  return { api, fetch: appleFetchInstance };
}

export async function loginAppleDeveloperAccount(request: AppleDeveloperLoginRequest): Promise<AppleDeveloperContext> {
  const appleId = request.credentials.appleId.trim();
  const password = request.credentials.password;
  if (!appleId || !password) {
    throw new Error('Cannot login Apple account: Apple ID or password is empty');
  }

  const log = request.onLog ?? (() => undefined);
  log(`Login stage: authenticating Apple account ${maskEmail(appleId)}...`);

  // Reset the shared fetch instance so each login attempt starts with a fresh
  // libcurl TCP connection — prevents state bleed between accounts and between
  // a cancelled-then-retried login on the same account.
  appleFetchInstance = null;

  const verificationCallback = (submitCode: (code: string) => void) => {
    if (!request.onTwoFactorRequired) {
      throw new Error('2FA required but no in-page handler provided');
    }
    // The patched handleTwoFactor passes a TwoFactorContext; the raw altsign.js
    // VerificationHandler signature still receives `submitCode` as first arg,
    // but our patch replaces that with the full context object.
    const ctx = submitCode as unknown as TwoFactorContext;
    request.onTwoFactorRequired(ctx);
  };

  let { api } = await getAppleApi(log);

  let session: AppleDeveloperSession;
  try {
    ({ session } = await api.authenticate(appleId, password, request.anisetteData, verificationCallback));
  } catch (e) {
    // After 2FA at the apptokens stage, Apple invalidates the SRP session.
    // The sendAuthRequest patch throws REAUTH_SENTINEL to signal this.
    // We create a completely fresh AppleAPI (new auth state, new patches) and
    // retry the full SRP exchange with fresh anisette.
    if (e instanceof Error && e.message === REAUTH_SENTINEL) {
      log('Login stage: 2FA verified — restarting SRP with fresh session...');
      // Reset the shared fetch instance so the re-auth uses a fresh libcurl
      // TCP connection to Apple — eliminates connection-state as a failure cause.
      appleFetchInstance = null;
      const fresh = await getAppleApi(log);
      api = fresh.api;
      const { getAnisetteData } = await import('./anisette-service');
      const freshAnisette = await getAnisetteData();
      try {
        ({ session } = await api.authenticate(appleId, password, freshAnisette, verificationCallback));
      } catch (reauth2) {
        // If the fresh SRP exchange also hits the apptokens 2FA gate (rare),
        // REAUTH_SENTINEL escapes here. Surface it as a human-readable error
        // instead of exposing the internal sentinel string.
        if (reauth2 instanceof Error && reauth2.message === REAUTH_SENTINEL) {
          throw new Error('Authentication failed after two-factor verification. Please sign in again.');
        }
        throw reauth2;
      }
    } else {
      throw e;
    }
  }

  log('Login stage: fetching team/certificates/devices...');
  const team = await api.fetchTeam(session);
  const [certificates, devices] = await Promise.all([
    api.fetchCertificates(session, team),
    api.fetchDevices(session, team).catch(() => [] as Device[]),
  ]);

  log(`Login stage: team=${team.identifier} (${team.name}), certs=${certificates.length}, devices=${devices.length}.`);

  return {
    appleId,
    session,
    team,
    certificates,
    devices,
  };
}

export async function refreshAppleDeveloperContext(
  context: AppleDeveloperContext,
  onLog?: (message: string) => void,
): Promise<AppleDeveloperContext> {
  const log = onLog ?? (() => undefined);
  const { api } = await getAppleApi();
  log('Signing stage: refreshing team/certificates/devices...');
  const team = await api.fetchTeam(context.session);
  const [certificates, devices] = await Promise.all([
    api.fetchCertificates(context.session, team),
    api.fetchDevices(context.session, team).catch(() => [] as Device[]),
  ]);
  log(`Signing stage: refreshed team=${team.identifier}, certs=${certificates.length}, devices=${devices.length}.`);
  return {
    ...context,
    team,
    certificates,
    devices,
  };
}

export async function signIpaWithApple(request: AppleSigningRequest): Promise<AppleSigningResult> {
  const context = await loginAppleDeveloperAccount({
    anisetteData: request.anisetteData,
    credentials: request.credentials,
    onLog: request.onLog,
  });
  return await signIpaWithAppleContext({
    ipaFile: request.ipaFile,
    context,
    deviceUdid: request.deviceUdid,
    deviceName: request.deviceName,
    bundleIdOverride: request.bundleIdOverride,
    displayNameOverride: request.displayNameOverride,
    onLog: request.onLog,
  });
}

export async function signIpaWithAppleContext(request: AppleSigningWithContextRequest): Promise<AppleSigningResult> {
  const { ipaFile, context, onLog } = request;
  const ipaData = new Uint8Array(await ipaFile.arrayBuffer());
  const ipaInfo = readIpaInfo(ipaData);

  const bundleIdBase = (request.bundleIdOverride ?? ipaInfo.bundleId ?? '').trim();
  if (bundleIdBase.length === 0) {
    throw new Error('Cannot sign IPA: bundle identifier is missing');
  }

  const { api } = await getAppleApi();
  const team = context.team;
  onLog(`Signing stage: using team ${team.identifier} (${team.name}).`);

  const finalBundleId = buildTeamScopedBundleId(bundleIdBase, team.identifier);
  const displayName = (request.displayNameOverride ?? ipaInfo.displayName ?? '').trim();

  const identity = await ensureSigningIdentity(api, context.session, team, context.appleId, onLog);
  await ensureDeviceRegistered(api, context.session, team, request.deviceUdid, request.deviceName, onLog);
  const appId = await ensureAppId(api, context.session, team, finalBundleId, onLog);

  onLog('Signing stage: fetching provisioning profile...');
  const provisioningProfile = await api.fetchProvisioningProfile(context.session, team, appId);

  onLog('Signing stage: resigning IPA in browser...');
  const { signIPA } = await loadAltsignModule();
  const signed = await signIPA({
    ipaData,
    certificate: identity.certificate.publicKey,
    privateKey: identity.privateKey,
    provisioningProfile: provisioningProfile.data,
    bundleID: finalBundleId,
    displayName: displayName.length > 0 ? displayName : undefined,
    adhoc: false,
    forceSign: true,
  });

  const outputFileName = toSignedFileName(ipaFile.name);
  const signedArray = new Uint8Array(signed.data.byteLength);
  signedArray.set(signed.data);
  const signedBuffer = signedArray.buffer.slice(0);
  const signedFile = new File([signedBuffer], outputFileName, {
    type: 'application/octet-stream',
  });
  onLog(`Signing stage: complete (${signed.data.byteLength} bytes).`);

  return {
    signedFile,
    outputBundleId: finalBundleId,
    teamId: team.identifier,
  };
}

async function ensureSigningIdentity(
  api: AppleAPI,
  session: { anisetteData: AnisetteData; dsid: string; authToken: string },
  team: Team,
  appleId: string,
  onLog: (message: string) => void,
): Promise<{ certificate: Certificate; privateKey: Uint8Array }> {
  const certificates = await api.fetchCertificates(session, team);
  const cached = loadCachedSigningIdentity(appleId, team.identifier);

  if (cached) {
    const matched = certificates.find((item) => item.identifier === cached.certId);
    if (matched) {
      onLog(`Signing stage: using cached certificate ${matched.identifier}.`);
      return {
        certificate: {
          ...matched,
          publicKey: base64ToBytes(cached.certPublicKeyBase64),
        },
        privateKey: base64ToBytes(cached.privateKeyBase64),
      };
    }
  }

  onLog('Signing stage: creating development certificate...');
  let created: { certificate: Certificate; privateKey: Uint8Array };
  try {
    created = await api.addCertificate(session, team, `webmuxd-${Date.now()}`);
  } catch (error) {
    const message = String(error);
    if (!message.includes('7460') || certificates.length === 0) {
      throw error;
    }
    const target = certificates[0];
    onLog(`Signing stage: certificate limit hit, revoking ${target.identifier}...`);
    await api.revokeCertificate(session, team, target);
    created = await api.addCertificate(session, team, `webmuxd-${Date.now()}`);
  }

  saveCachedSigningIdentity(appleId, team.identifier, {
    certId: created.certificate.identifier,
    certPublicKeyBase64: bytesToBase64(created.certificate.publicKey),
    privateKeyBase64: bytesToBase64(created.privateKey),
  });
  onLog(`Signing stage: certificate ready ${created.certificate.identifier}.`);
  return created;
}

async function ensureDeviceRegistered(
  api: AppleAPI,
  session: { anisetteData: AnisetteData; dsid: string; authToken: string },
  team: Team,
  deviceUdid: string,
  deviceName: string | undefined,
  onLog: (message: string) => void,
): Promise<void> {
  const normalizedUdid = normalizeUdid(deviceUdid);
  if (!normalizedUdid) {
    onLog('Signing stage: skip device registration because UDID is empty.');
    return;
  }

  let devices: Device[] = [];
  try {
    devices = await api.fetchDevices(session, team);
  } catch (error) {
    onLog(`Signing stage: fetchDevices failed, skip registration check: ${formatError(error)}`);
  }
  const existed = findRegisteredDevice(devices, normalizedUdid);
  if (existed) {
    onLog(`Signing stage: device already registered (${existed.identifier}).`);
    return;
  }

  const registerName =
    deviceName && deviceName.trim().length > 0 ? deviceName.trim() : `webmuxd-${normalizedUdid.slice(-6)}`;
  try {
    onLog(`Signing stage: registering device ${normalizedUdid} as ${registerName}...`);
    await api.registerDevice(session, team, registerName, normalizedUdid);
    onLog(`Signing stage: device registered (${normalizedUdid}).`);
  } catch (error) {
    onLog(`Signing stage: register failed, skip and continue: ${formatError(error)}`);
    try {
      const latestDevices = await api.fetchDevices(session, team);
      const registered = findRegisteredDevice(latestDevices, normalizedUdid);
      if (registered) {
        onLog(`Signing stage: device confirmed in developer list (${registered.identifier}).`);
        return;
      }
    } catch (verifyError) {
      onLog(`Signing stage: device verify after failure also failed: ${formatError(verifyError)}`);
    }
    onLog('Signing stage: continue without registration (may affect profile generation).');
    return;
  }

  try {
    const latestDevices = await api.fetchDevices(session, team);
    const registered = findRegisteredDevice(latestDevices, normalizedUdid);
    if (registered) {
      onLog(`Signing stage: device confirmed in developer list (${registered.identifier}).`);
    }
  } catch (error) {
    onLog(`Signing stage: device verification skipped: ${formatError(error)}`);
  }
}

async function ensureAppId(
  api: AppleAPI,
  session: { anisetteData: AnisetteData; dsid: string; authToken: string },
  team: Team,
  bundleId: string,
  onLog: (message: string) => void,
): Promise<AppID> {
  const appIds = await api.fetchAppIDs(session, team);
  const matched = appIds.find((item) => item.bundleIdentifier === bundleId);
  if (matched) {
    onLog(`Signing stage: reuse App ID ${bundleId}.`);
    return matched;
  }
  onLog(`Signing stage: creating App ID ${bundleId}...`);
  return api.addAppID(session, team, 'WebMuxD Signed App', bundleId);
}

function readIpaInfo(ipaBytes: Uint8Array): ParsedIpaInfo {
  const files = unzipSync(ipaBytes, {
    filter: (file) => PRIMARY_APP_INFO_PLIST_RE.test(file.name),
  });
  const infoName = Object.keys(files).find((name) => PRIMARY_APP_INFO_PLIST_RE.test(name));
  if (!infoName) {
    return {};
  }
  const plistData = parseInfoPlist(files[infoName]);
  if (!plistData || typeof plistData !== 'object' || Array.isArray(plistData)) {
    return {};
  }
  const data = plistData as Record<string, unknown>;
  const bundleId = typeof data.CFBundleIdentifier === 'string' ? (data.CFBundleIdentifier as string) : undefined;
  const displayName =
    typeof data.CFBundleDisplayName === 'string'
      ? (data.CFBundleDisplayName as string)
      : typeof data.CFBundleName === 'string'
      ? (data.CFBundleName as string)
      : undefined;
  return { bundleId, displayName };
}

function parseInfoPlist(infoPlistBytes: Uint8Array): unknown {
  if (strFromU8(infoPlistBytes.subarray(0, 8)) === 'bplist00') {
    return parseBinaryPlist(infoPlistBytes);
  }
  const xml = strFromU8(infoPlistBytes);
  return parseXmlPlist(xml);
}

function parseXmlPlist(xml: string): unknown {
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const parserError = doc.querySelector('parsererror');
  if (parserError) {
    return {};
  }
  const root = doc.querySelector('plist > *');
  if (!root) {
    return {};
  }
  return parseXmlNode(root);
}

function parseXmlNode(node: Element): unknown {
  switch (node.tagName) {
    case 'dict': {
      const map: Record<string, unknown> = {};
      const children = Array.from(node.children);
      for (let i = 0; i < children.length - 1; i += 2) {
        const keyNode = children[i];
        const valueNode = children[i + 1];
        if (keyNode.tagName !== 'key') {
          continue;
        }
        map[keyNode.textContent ?? ''] = parseXmlNode(valueNode);
      }
      return map;
    }
    case 'array':
      return Array.from(node.children).map((child) => parseXmlNode(child));
    case 'string':
    case 'date':
      return node.textContent ?? '';
    case 'integer':
      return Number.parseInt(node.textContent ?? '0', 10);
    case 'real':
      return Number.parseFloat(node.textContent ?? '0');
    case 'true':
      return true;
    case 'false':
      return false;
    case 'data':
      return base64ToBytes((node.textContent ?? '').trim());
    default:
      return node.textContent ?? '';
  }
}

function parseBinaryPlist(bytes: Uint8Array): unknown {
  if (bytes.length < 40 || strFromU8(bytes.subarray(0, 8)) !== 'bplist00') {
    throw new Error('Invalid binary plist');
  }

  const trailerOffset = bytes.length - 32;
  const offsetSize = bytes[trailerOffset + 6];
  const objectRefSize = bytes[trailerOffset + 7];
  const objectCount = readUInt(bytes, trailerOffset + 8, 8);
  const topObject = readUInt(bytes, trailerOffset + 16, 8);
  const offsetTableStart = readUInt(bytes, trailerOffset + 24, 8);

  const objectOffsets = new Array<number>(objectCount);
  for (let i = 0; i < objectCount; i += 1) {
    const entryOffset = offsetTableStart + i * offsetSize;
    objectOffsets[i] = readUInt(bytes, entryOffset, offsetSize);
  }

  const memo = new Map<number, unknown>();

  const readLength = (offset: number, objectInfo: number): { length: number; nextOffset: number } => {
    if (objectInfo < 0x0f) {
      return { length: objectInfo, nextOffset: offset + 1 };
    }
    const marker = bytes[offset + 1];
    const markerType = marker >> 4;
    const markerInfo = marker & 0x0f;
    if (markerType !== 0x1) {
      throw new Error('Invalid binary plist length marker');
    }
    const intSize = 1 << markerInfo;
    const intOffset = offset + 2;
    return {
      length: readUInt(bytes, intOffset, intSize),
      nextOffset: intOffset + intSize,
    };
  };

  const parseObject = (index: number): unknown => {
    if (memo.has(index)) {
      return memo.get(index);
    }
    const offset = objectOffsets[index];
    const marker = bytes[offset];
    const objectType = marker >> 4;
    const objectInfo = marker & 0x0f;

    let value: unknown;
    if (objectType === 0x0) {
      value = objectInfo === 0x8 ? false : objectInfo === 0x9;
    } else if (objectType === 0x1) {
      value = readUInt(bytes, offset + 1, 1 << objectInfo);
    } else if (objectType === 0x2) {
      const realSize = 1 << objectInfo;
      const view = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, realSize);
      value = realSize === 4 ? view.getFloat32(0, false) : view.getFloat64(0, false);
    } else if (objectType === 0x5) {
      const { length, nextOffset } = readLength(offset, objectInfo);
      value = strFromU8(bytes.subarray(nextOffset, nextOffset + length));
    } else if (objectType === 0x6) {
      const { length, nextOffset } = readLength(offset, objectInfo);
      value = decodeUtf16Be(bytes.subarray(nextOffset, nextOffset + length * 2));
    } else if (objectType === 0xa) {
      const { length, nextOffset } = readLength(offset, objectInfo);
      const items: unknown[] = [];
      for (let i = 0; i < length; i += 1) {
        const ref = readUInt(bytes, nextOffset + i * objectRefSize, objectRefSize);
        items.push(parseObject(ref));
      }
      value = items;
    } else if (objectType === 0xd) {
      const { length, nextOffset } = readLength(offset, objectInfo);
      const map: Record<string, unknown> = {};
      const valuesOffset = nextOffset + length * objectRefSize;
      for (let i = 0; i < length; i += 1) {
        const keyRef = readUInt(bytes, nextOffset + i * objectRefSize, objectRefSize);
        const valueRef = readUInt(bytes, valuesOffset + i * objectRefSize, objectRefSize);
        const key = parseObject(keyRef);
        if (typeof key === 'string') {
          map[key] = parseObject(valueRef);
        }
      }
      value = map;
    } else {
      value = null;
    }

    memo.set(index, value);
    return value;
  };

  return parseObject(topObject);
}

function readUInt(bytes: Uint8Array, offset: number, length: number): number {
  let value = 0;
  for (let i = 0; i < length; i += 1) {
    value = value * 256 + bytes[offset + i];
  }
  return value;
}

function decodeUtf16Be(bytes: Uint8Array): string {
  let text = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    text += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
  }
  return text;
}

function buildTeamScopedBundleId(baseBundleId: string, teamId: string): string {
  const trimmedBase = baseBundleId.trim();
  const trimmedTeam = teamId.trim();
  if (!trimmedBase || !trimmedTeam) {
    return trimmedBase;
  }
  const lowerBase = trimmedBase.toLowerCase();
  const lowerTeam = trimmedTeam.toLowerCase();
  if (lowerBase.endsWith(`.${lowerTeam}`)) {
    return trimmedBase;
  }
  return `${trimmedBase}.${trimmedTeam}`;
}

function toSignedFileName(name: string): string {
  if (!name.toLowerCase().endsWith('.ipa')) {
    return `${name}-signed.ipa`;
  }
  return `${name.slice(0, -4)}-signed.ipa`;
}

function loadCachedSigningIdentity(appleId: string, teamId: string): CachedSigningIdentityPayload | null {
  const map = loadSigningIdentityMap();
  const key = signingIdentityKey(appleId, teamId);
  const value = map[key];
  if (!value || !value.certId || !value.certPublicKeyBase64 || !value.privateKeyBase64) {
    return null;
  }
  return value;
}

function saveCachedSigningIdentity(appleId: string, teamId: string, payload: CachedSigningIdentityPayload): void {
  const map = loadSigningIdentityMap();
  map[signingIdentityKey(appleId, teamId)] = payload;
  window.localStorage.setItem(SIGNING_IDENTITY_STORAGE_KEY, JSON.stringify(map));
}

function loadSigningIdentityMap(): StoredSigningIdentityMap {
  const raw = window.localStorage.getItem(SIGNING_IDENTITY_STORAGE_KEY);
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }
    return parsed as StoredSigningIdentityMap;
  } catch {
    return {};
  }
}

function signingIdentityKey(appleId: string, teamId: string): string {
  return `${appleId.trim().toLowerCase()}::${teamId.trim().toUpperCase()}`;
}

function bytesToBase64(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const normalized = base64.replace(/\s+/g, '');
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function maskEmail(value: string): string {
  const trimmed = value.trim();
  const at = trimmed.indexOf('@');
  if (at <= 1) {
    return '***';
  }
  return `${trimmed.slice(0, 2)}***${trimmed.slice(at)}`;
}

function findRegisteredDevice(devices: readonly Device[], normalizedUdid: string): Device | null {
  return devices.find((item) => normalizeUdid(item.identifier) === normalizedUdid) ?? null;
}

function normalizeUdid(value: string): string {
  return value.trim().toUpperCase();
}

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
