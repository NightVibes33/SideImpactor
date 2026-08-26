import { useState } from 'react';
import { Button } from './ui/Button';
import { DropZone } from './DropZone';
import { DevicePicker } from './DevicePicker';
import type { StoredAccountSummary } from '../lib/account-session';
import { signIpaLocalFlow } from '../flows/sign';

interface SignPageProps {
  file: File | null;
  onFileChange: (file: File | null) => void;

  accounts: StoredAccountSummary[];
  activeAccountKey: string | null;
  onAccountChange: (key: string) => void;

  knownUdids: string[];
  connectedUdid: string | null;
  selectedUdid: string;
  onSelectedUdidChange: (value: string) => void;

  onPair: () => void;
  pairBusy: boolean;
  pairDisabled: boolean;

  onSign: () => void;
  signBusy: boolean;
  signDisabled: boolean;

  onInstall: () => void;
  installBusy: boolean;
  installDisabled: boolean;
}

function accountKey(s: StoredAccountSummary): string {
  return `${s.appleId.trim().toLowerCase()}::${s.teamId.trim().toUpperCase()}`;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function downloadSignedFile(file: File): void {
  const url = URL.createObjectURL(file);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = file.name;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function SignPage({
  file,
  onFileChange,
  accounts,
  activeAccountKey,
  onAccountChange,
  knownUdids,
  connectedUdid,
  selectedUdid,
  onSelectedUdidChange,
  onPair,
  pairBusy,
  pairDisabled,
  onSign,
  signBusy,
  signDisabled,
  onInstall,
  installBusy,
  installDisabled,
}: SignPageProps) {
  const [localP12File, setLocalP12File] = useState<File | null>(null);
  const [localProvisionFile, setLocalProvisionFile] = useState<File | null>(null);
  const [localP12Password, setLocalP12Password] = useState('');
  const [localBusy, setLocalBusy] = useState(false);
  const [localStatus, setLocalStatus] = useState<string | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const localSignDisabled = localBusy || !file || !localP12File || !localProvisionFile;

  const handleLocalSign = async () => {
    if (localSignDisabled || !file || !localP12File || !localProvisionFile) return;

    setLocalBusy(true);
    setLocalError(null);
    setLocalStatus('Loading local signer…');
    try {
      const result = await signIpaLocalFlow({
        ipaFile: file,
        p12File: localP12File,
        p12Password: localP12Password,
        provisioningProfileFile: localProvisionFile,
        log: (message) => setLocalStatus(message),
      });
      setLocalStatus(`Signed locally: ${result.signedFile.name}`);
      downloadSignedFile(result.signedFile);
    } catch (error) {
      setLocalStatus(null);
      setLocalError(formatError(error));
    } finally {
      setLocalBusy(false);
    }
  };

  return (
    <section className="space-y-6 anim-in">
      <div>
        <h1 className="text-[clamp(1.75rem,3.5vw,2.1rem)] font-semibold tracking-tight text-ink">Sign &amp; Install</h1>
        <p className="mt-2 text-[14.5px] text-muted">Drop an .ipa, then sign and install onto your paired device.</p>
      </div>

      <DropZone file={file} onFileChange={onFileChange} />

      <div className="rounded-2xl border border-line bg-panel p-4 sm:p-5">
        <div className="mb-4">
          <h2 className="text-[15px] font-semibold text-ink">Local certificate signing</h2>
          <p className="mt-1 text-[12.5px] text-muted">
            Use a .p12 and .mobileprovision directly in this browser. The signing files are not uploaded.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="local-p12" className="mb-1.5 block text-[12.5px] font-medium text-muted">
              P12 certificate
            </label>
            <input
              id="local-p12"
              className="field-input"
              type="file"
              accept=".p12,.pfx,application/x-pkcs12"
              onChange={(event) => {
                setLocalP12File(event.target.files?.[0] ?? null);
                setLocalError(null);
                setLocalStatus(null);
              }}
            />
          </div>

          <div>
            <label htmlFor="local-profile" className="mb-1.5 block text-[12.5px] font-medium text-muted">
              Provisioning profile
            </label>
            <input
              id="local-profile"
              className="field-input"
              type="file"
              accept=".mobileprovision,application/octet-stream"
              onChange={(event) => {
                setLocalProvisionFile(event.target.files?.[0] ?? null);
                setLocalError(null);
                setLocalStatus(null);
              }}
            />
          </div>
        </div>

        <div className="mt-4">
          <label htmlFor="local-p12-password" className="mb-1.5 block text-[12.5px] font-medium text-muted">
            P12 password
          </label>
          <input
            id="local-p12-password"
            className="field-input"
            type="password"
            autoComplete="off"
            value={localP12Password}
            placeholder="Leave blank if the P12 has no password"
            onChange={(event) => {
              setLocalP12Password(event.target.value);
              setLocalError(null);
            }}
          />
        </div>

        {localError ? (
          <p className="mt-3 text-[12.5px] text-red-600" role="alert">
            {localError}
          </p>
        ) : localStatus ? (
          <p className="mt-3 text-[12.5px] text-muted" aria-live="polite">
            {localStatus}
          </p>
        ) : null}

        <div className="mt-4 flex justify-end">
          <Button
            variant="primary"
            busy={localBusy}
            busyLabel="Signing locally…"
            disabled={localSignDisabled}
            onClick={() => void handleLocalSign()}
            className="min-w-[190px]"
          >
            Sign &amp; Download Locally
          </Button>
        </div>
      </div>

      <div>
        <label htmlFor="account-select" className="mb-1.5 block text-[12.5px] font-medium text-muted">
          Apple Signing Account
        </label>
        <select
          id="account-select"
          className="field-input field-select"
          value={activeAccountKey ?? ''}
          onChange={(e) => onAccountChange(e.target.value)}
        >
          <option value="">{accounts.length > 0 ? 'Select account' : 'No account'}</option>
          {accounts.map((acct) => {
            const key = accountKey(acct);
            return (
              <option key={key} value={key}>
                {acct.appleId} / {acct.teamId}
              </option>
            );
          })}
        </select>
      </div>

      <DevicePicker
        knownUdids={knownUdids}
        connectedUdid={connectedUdid}
        selectedUdid={selectedUdid}
        onSelectedChange={onSelectedUdidChange}
        onPair={onPair}
        pairing={pairBusy}
        pairDisabled={pairDisabled}
      />

      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button
          variant="ghost"
          busy={signBusy}
          busyLabel="Signing…"
          disabled={signDisabled}
          onClick={onSign}
          className="min-w-[120px]"
        >
          Sign IPA
        </Button>
        <Button
          variant="primary"
          busy={installBusy}
          busyLabel="Installing…"
          disabled={installDisabled}
          onClick={onInstall}
          className="min-w-[160px]"
        >
          Install Signed IPA
        </Button>
      </div>
    </section>
  );
}
