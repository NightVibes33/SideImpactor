import type { ChangeEvent } from 'react';
import { Button } from './ui/Button';
import { Field } from './ui/Field';

interface LoginModalProps {
  open: boolean;
  onClose: () => void;
  appleId: string;
  password: string;
  busyLoginSign: boolean;
  canSubmit: boolean;
  error?: string | null;
  onAppleIdChange: (value: string) => void;
  onAppleIdBlur: () => void;
  onPasswordChange: (value: string) => void;
  onSubmit: () => void;
}

export function LoginModal({
  open,
  onClose,
  appleId,
  password,
  busyLoginSign,
  canSubmit,
  error,
  onAppleIdChange,
  onAppleIdBlur,
  onPasswordChange,
  onSubmit,
}: LoginModalProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/30 backdrop-blur-sm p-4 pt-[8vh]">
      <div className="w-full max-w-110 rounded-2xl border border-border bg-bg p-6 shadow-2xl anim-in">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-[18px] font-semibold tracking-tight text-ink">Add Account</h2>
          <button
            type="button"
            onClick={onClose}
            disabled={busyLoginSign}
            className="flex h-7 w-7 items-center justify-center rounded-full text-muted transition-colors hover:bg-surface hover:text-ink disabled:opacity-40"
          >
            <svg
              className="h-4 w-4"
              viewBox="0 0 16 16"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            >
              <path d="M4 4l8 8M12 4l-8 8" />
            </svg>
          </button>
        </div>

        <div className="space-y-4">
          <Field
            label="Apple ID"
            type="email"
            autoComplete="username"
            placeholder="you@icloud.com"
            value={appleId}
            onChange={(e: ChangeEvent<HTMLInputElement>) => onAppleIdChange(e.target.value)}
            onBlur={onAppleIdBlur}
          />
          <Field
            label="Password"
            type="password"
            autoComplete="current-password"
            placeholder="Apple ID password"
            value={password}
            onChange={(e: ChangeEvent<HTMLInputElement>) => onPasswordChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && canSubmit && !busyLoginSign) {
                e.preventDefault();
                onSubmit();
              }
            }}
          />
        </div>

        <div className="mt-4 space-y-1">
          <p className="text-[11.5px] text-muted">
            Your credentials are stored locally in this browser and are sent directly to Apple.
          </p>
          <p className="text-[11.5px] text-danger underline underline-offset-2 decoration-danger/40">
            Verify that you trust the server hosting this page. A compromised server can intercept your credentials.
          </p>
        </div>

        <div className="mt-5 flex flex-col gap-3">
          {error && (
            <p className="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
              {error}
            </p>
          )}
          <div className="flex justify-end">
            <Button
              variant="primary"
              busy={busyLoginSign}
              busyLabel="Signing In…"
              disabled={!canSubmit}
              onClick={onSubmit}
              className="min-w-35"
            >
              Sign In
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
