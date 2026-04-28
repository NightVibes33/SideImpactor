import { useEffect, useRef, useState } from 'react';
import { Modal } from './ui/Modal';
import { Button } from './ui/Button';
import type { TrustedPhoneNumber, TwoFactorContext } from '../apple-signing';

type Mode = 'device' | 'sms';

interface TwoFactorModalProps {
  open: boolean;
  ctx: TwoFactorContext | null;
  onCancel: () => void;
  /** Server-side error passed back from the login flow after a failed verify. */
  serverError?: string | null;
  /** Called when the user wants to retry the entire login after a server error. */
  onRetry?: () => void;
}

export function TwoFactorModal({ open, ctx, onCancel, serverError, onRetry }: TwoFactorModalProps) {
  const [mode, setMode] = useState<Mode>('device');
  const [selectedPhone, setSelectedPhone] = useState<TrustedPhoneNumber | null>(null);
  const [code, setCode] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [smsSent, setSmsSent] = useState(false);
  const [smsBusy, setSmsBusy] = useState(false);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const displayError = serverError || localError;
  const phones = ctx?.trustedPhoneNumbers ?? [];

  // Reset state on open/close
  useEffect(() => {
    if (open) {
      setMode('device');
      setCode('');
      setLocalError(null);
      setSmsSent(false);
      setSmsBusy(false);
      setVerifyBusy(false);
      setSelectedPhone(phones.length > 0 ? phones[0] : null);
      const timer = window.setTimeout(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      }, 0);
      return () => window.clearTimeout(timer);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Focus input when switching modes or after SMS sent
  useEffect(() => {
    if (open && (mode === 'device' || smsSent)) {
      const timer = window.setTimeout(() => inputRef.current?.focus(), 50);
      return () => window.clearTimeout(timer);
    }
  }, [mode, smsSent, open]);

  const switchToSms = () => {
    setMode('sms');
    setCode('');
    setLocalError(null);
    setSmsSent(false);
  };

  const switchToDevice = () => {
    setMode('device');
    setCode('');
    setLocalError(null);
  };

  const handleRequestSms = async () => {
    if (!ctx || !selectedPhone) return;
    setSmsBusy(true);
    setLocalError(null);
    try {
      await ctx.requestSms(selectedPhone.id);
      setSmsSent(true);
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Failed to send SMS');
    } finally {
      setSmsBusy(false);
    }
  };

  const handleSubmit = async () => {
    const trimmed = code.trim();
    if (trimmed.length === 0) {
      setLocalError('Please enter the verification code.');
      return;
    }
    if (!ctx) return;

    setVerifyBusy(true);
    setLocalError(null);
    try {
      if (mode === 'device') {
        ctx.submitDeviceCode(trimmed);
        // submitDeviceCode resolves the outer Promise — no async result here
      } else {
        if (!selectedPhone) return;
        await ctx.submitSmsCode(selectedPhone.id, trimmed);
      }
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Verification failed');
      setVerifyBusy(false);
    }
    // On success the parent modal will close; don't clear busy so button stays
    // disabled until the modal is removed.
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (mode === 'sms' && !smsSent) {
        void handleRequestSms();
      } else {
        void handleSubmit();
      }
    }
  };

  return (
    <Modal open={open} onClose={onCancel} labelledBy="two-factor-title" closeOnBackdrop={false}>
      <h2 id="two-factor-title" className="text-[16px] font-semibold tracking-tight text-ink">
        Two-Factor Authentication
      </h2>

      {mode === 'device' ? (
        <>
          <p className="mt-1.5 text-[13px] leading-[1.55] text-muted">
            Enter the verification code from your trusted Apple device or Mac.
          </p>

          <label htmlFor="two-factor-code" className="mt-5 mb-1.5 block text-[12.5px] font-medium text-muted">
            Verification Code
          </label>
          <input
            ref={inputRef}
            id="two-factor-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            placeholder="123456"
            className="field-input font-mono text-center text-[18px] tracking-[0.3em]"
            value={code}
            onChange={(e) => { setCode(e.target.value); setLocalError(null); }}
            onKeyDown={handleKeyDown}
          />
          <p className="mt-2 min-h-[18px] text-[12px] text-[var(--color-danger)]">{displayError ?? ''}</p>

          <div className="mt-4 grid grid-cols-2 gap-2">
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
            {serverError ? (
              <Button variant="primary" onClick={onRetry}>
                Retry Login
              </Button>
            ) : (
              <Button
                variant="primary"
                busy={verifyBusy}
                busyLabel="Verifying…"
                onClick={() => void handleSubmit()}
                disabled={verifyBusy}
              >
                Verify
              </Button>
            )}
          </div>

          {phones.length > 0 && (
            <button
              type="button"
              onClick={switchToSms}
              className="mt-3 w-full text-center text-[12px] text-muted underline underline-offset-2 hover:text-ink transition-colors"
            >
              Get SMS instead →
            </button>
          )}
        </>
      ) : (
        <>
          <p className="mt-1.5 text-[13px] leading-[1.55] text-muted">
            {smsSent
              ? 'Enter the code sent via SMS.'
              : 'Choose a phone number to receive a verification code.'}
          </p>

          {/* Phone picker */}
          {!smsSent && phones.length > 1 && (
            <div className="mt-4 space-y-1">
              {phones.map((phone) => (
                <button
                  key={phone.id}
                  type="button"
                  onClick={() => setSelectedPhone(phone)}
                  className={`w-full rounded-lg border px-3 py-2 text-left text-[13px] transition-colors ${
                    selectedPhone?.id === phone.id
                      ? 'border-blue-500 bg-blue-500/10 text-ink'
                      : 'border-border text-muted hover:border-blue-400 hover:text-ink'
                  }`}
                >
                  {phone.numberWithDialCode || phone.obfuscatedNumber}
                </button>
              ))}
            </div>
          )}

          {!smsSent && phones.length === 1 && (
            <p className="mt-3 rounded-lg border border-border px-3 py-2 text-[13px] text-muted">
              {phones[0].numberWithDialCode || phones[0].obfuscatedNumber}
            </p>
          )}

          <p className="mt-2 min-h-[18px] text-[12px] text-[var(--color-danger)]">{localError ?? ''}</p>

          {!smsSent ? (
            <div className="mt-2 grid grid-cols-2 gap-2">
              <Button variant="ghost" onClick={switchToDevice}>Back</Button>
              <Button
                variant="primary"
                busy={smsBusy}
                busyLabel="Sending…"
                disabled={!selectedPhone || smsBusy}
                onClick={() => void handleRequestSms()}
              >
                Send SMS
              </Button>
            </div>
          ) : (
            <>
              <label htmlFor="sms-code" className="mt-5 mb-1.5 block text-[12.5px] font-medium text-muted">
                SMS Code
              </label>
              <input
                ref={inputRef}
                id="sms-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                placeholder="123456"
                className="field-input font-mono text-center text-[18px] tracking-[0.3em]"
                value={code}
                onChange={(e) => { setCode(e.target.value); setLocalError(null); }}
                onKeyDown={handleKeyDown}
              />
              <p className="mt-2 min-h-[18px] text-[12px] text-[var(--color-danger)]">{displayError ?? ''}</p>
              <div className="mt-4 grid grid-cols-2 gap-2">
                <Button variant="ghost" onClick={() => { setSmsSent(false); setCode(''); }}>
                  Resend
                </Button>
                {serverError ? (
                  <Button variant="primary" onClick={onRetry}>
                    Retry Login
                  </Button>
                ) : (
                  <Button
                    variant="primary"
                    busy={verifyBusy}
                    busyLabel="Verifying…"
                    onClick={() => void handleSubmit()}
                    disabled={verifyBusy}
                  >
                    Verify
                  </Button>
                )}
              </div>
            </>
          )}
        </>
      )}
    </Modal>
  );
}
