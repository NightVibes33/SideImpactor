import type { AnisetteData } from '../anisette-service';
import type { AppleDeveloperContext } from '../apple-signing';
import { loadAppleSigningModule } from './login';

export interface SignIpaRequest {
  ipaFile: File;
  context: AppleDeveloperContext;
  anisetteData: AnisetteData;
  deviceUdid: string;
  deviceName?: string;
  log: (msg: string) => void;
}

export interface SignIpaResult {
  signedFile: File;
  context: AppleDeveloperContext;
}

export interface LocalSignIpaRequest {
  ipaFile: File;
  p12File: File;
  p12Password?: string;
  provisioningProfileFile: File;
  bundleIdOverride?: string;
  displayNameOverride?: string;
  log?: (msg: string) => void;
}

export interface LocalSignIpaResult {
  signedFile: File;
}

export async function signIpaFlow(req: SignIpaRequest): Promise<SignIpaResult> {
  const appleSigning = await loadAppleSigningModule();

  const contextWithAnisette: AppleDeveloperContext = {
    ...req.context,
    session: {
      ...req.context.session,
      anisetteData: req.anisetteData,
    },
  };

  const refreshed = await appleSigning.refreshAppleDeveloperContext(contextWithAnisette, req.log);

  req.log('sign: preparing ipa...');
  const result = await appleSigning.signIpaWithAppleContext({
    ipaFile: req.ipaFile,
    context: refreshed,
    deviceUdid: req.deviceUdid,
    deviceName: req.deviceName,
    onLog: req.log,
  });
  req.log(`sign: done -> ${result.signedFile.name}`);

  return { signedFile: result.signedFile, context: refreshed };
}

/**
 * Resign an IPA entirely in the browser with an imported P12 and provisioning
 * profile. No Apple login/session or server-side signing service is involved.
 */
export async function signIpaLocalFlow(req: LocalSignIpaRequest): Promise<LocalSignIpaResult> {
  const log = req.log ?? (() => undefined);
  log('local sign: loading signer...');

  const { createResigner } = await import('@lbr77/zsign-wasm-resigner-wrapper');
  const resigner = await createResigner();

  log('local sign: reading ipa, p12, and provisioning profile...');
  const [ipaData, p12Data, provisioningProfile] = await Promise.all([
    fileBytes(req.ipaFile),
    fileBytes(req.p12File),
    fileBytes(req.provisioningProfileFile),
  ]);

  log('local sign: resigning ipa in browser...');
  const signedResult = await resigner.signIpa(ipaData, {
    pkey: p12Data,
    prov: provisioningProfile,
    password: req.p12Password ?? '',
    bundleId: cleanOptional(req.bundleIdOverride),
    displayName: cleanOptional(req.displayNameOverride),
    adhoc: false,
    forceSign: true,
    enableCache: false,
    zipLevel: 9,
  });

  const signedData = signedResult.data;
  const owned = new Uint8Array(signedData.byteLength);
  owned.set(signedData);
  const signedFile = new File([owned.buffer], toSignedFileName(req.ipaFile.name), {
    type: 'application/octet-stream',
  });

  log(`local sign: done -> ${signedFile.name}`);
  return { signedFile };
}

async function fileBytes(file: File): Promise<Uint8Array> {
  return new Uint8Array(await file.arrayBuffer());
}

function cleanOptional(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function toSignedFileName(name: string): string {
  const clean = name.trim() || 'app.ipa';
  if (/\.ipa$/i.test(clean)) {
    return clean.replace(/\.ipa$/i, '-signed.ipa');
  }
  return `${clean}-signed.ipa`;
}
