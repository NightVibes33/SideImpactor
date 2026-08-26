import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AnisetteData } from './anisette-service';
import type { AppleDeveloperContext, TwoFactorContext } from './apple-signing';
import type { PairedDeviceInfo } from './flows/pair';

// ---- mock every flow module ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const pairDeviceFlowMock = vi.fn<(ctx: any) => Promise<PairedDeviceInfo>>();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ensureClientSelectedMock = vi.fn<(ctx: any) => Promise<any>>();
const isPairingDialogPendingErrorMock = vi.fn<(error: unknown) => boolean>();

vi.mock('./flows/pair', () => ({
  pairDeviceFlow: (ctx: unknown) => pairDeviceFlowMock(ctx),
  ensureClientSelected: (ctx: unknown) => ensureClientSelectedMock(ctx),
  isPairingDialogPendingError: (err: unknown) => isPairingDialogPendingErrorMock(err),
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ensureAnisetteMock = vi.fn<(existing: any) => Promise<{ anisetteData: AnisetteData; provisioned: boolean }>>();
const checkProvisionedMock = vi.fn<() => Promise<boolean>>();
const loginAccountMock =
  vi.fn<
    (req: {
      appleId: string;
      password: string;
      onTwoFactorRequired: (ctx: TwoFactorContext) => void;
      log: (msg: string) => void;
    }) => Promise<AppleDeveloperContext>
  >();

vi.mock('./flows/login', () => ({
  ensureAnisetteData: (existing: AnisetteData | null) => ensureAnisetteMock(existing),
  checkAnisetteProvisioned: () => checkProvisionedMock(),
  loginAccount: (req: Parameters<typeof loginAccountMock>[0]) => loginAccountMock(req),
  loadAnisetteService: async () => ({}),
  loadAppleSigningModule: async () => ({}),
}));

const signIpaFlowMock = vi.fn();
vi.mock('./flows/sign', () => ({
  signIpaFlow: (req: unknown) => signIpaFlowMock(req),
}));

const installFlowMock = vi.fn();
vi.mock('./flows/install', () => ({
  installFlow: (req: unknown) => installFlowMock(req),
}));

vi.mock('webmuxd', () => ({}));

// ---- fixtures ----

const fakeAnisette: AnisetteData = {
  machineID: 'MID',
  oneTimePassword: 'OTP',
  localUserID: 'LUID',
  routingInfo: 17106176,
  deviceUniqueIdentifier: 'DUI',
  deviceDescription: 'desc',
  deviceSerialNumber: '0',
  date: new Date('2024-01-01T00:00:00.000Z'),
  locale: 'en_US',
  timeZone: 'UTC',
};

const fakeContext: AppleDeveloperContext = {
  appleId: 'user@example.com',
  session: {
    anisetteData: fakeAnisette,
    dsid: 'dsid-1',
    authToken: 'auth-1',
  },
  team: { identifier: 'TEAMX', name: 'Team X' } as AppleDeveloperContext['team'],
  certificates: [],
  devices: [],
};

import { App } from './App';

beforeEach(() => {
  window.localStorage.clear();
  window.location.hash = '';
  Object.defineProperty(navigator, 'usb', {
    configurable: true,
    value: {},
  });
  checkProvisionedMock.mockResolvedValue(false);
  ensureAnisetteMock.mockResolvedValue({ anisetteData: fakeAnisette, provisioned: true });
  loginAccountMock.mockResolvedValue(fakeContext);
  isPairingDialogPendingErrorMock.mockReturnValue(false);
  pairDeviceFlowMock.mockResolvedValue({ udid: 'UDID-TEST', name: 'iPhone' });
  ensureClientSelectedMock.mockResolvedValue({ isSessionStarted: true, close: async () => {} });
  signIpaFlowMock.mockImplementation(async (req: { ipaFile: File; context: AppleDeveloperContext }) => ({
    signedFile: new File([new Uint8Array(8)], `signed-${req.ipaFile.name}`),
    context: req.context,
  }));
  installFlowMock.mockResolvedValue(undefined);
});

describe('App — page + nav', () => {
  it('mounts on the accounts page and defaults the URL hash', async () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Accounts' })).toBeInTheDocument();
    expect(window.location.hash).toBe('#/login');
    await waitFor(() => expect(checkProvisionedMock).toHaveBeenCalled());
  });

  it('navigates between accounts and sign pages via the header', async () => {
    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /Sign & Install/ }));
    expect(window.location.hash).toBe('#/sign');

    await userEvent.click(screen.getByRole('button', { name: 'Account' }));
    expect(window.location.hash).toBe('#/login');
  });
});

describe('App — pairing modal', () => {
  it('keeps trust pending separate from paired success and retries cleanly', async () => {
    const pendingError = new Error('Pair error=PairingDialogResponsePending');
    pairDeviceFlowMock
      .mockImplementationOnce(async (ctx) => {
        ctx.onTrustPending();
        throw pendingError;
      })
      .mockResolvedValueOnce({ udid: 'UDID-TEST', name: 'iPhone' });
    isPairingDialogPendingErrorMock.mockImplementation(
      (error) => error === pendingError || String(error).includes('PairingDialogResponsePending'),
    );

    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: /Sign & Install/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Connect Device' }));

    expect(await screen.findByText('Trust This Device')).toBeInTheDocument();
    expect(screen.queryByText('Device Paired')).toBeNull();

    await userEvent.click(screen.getByRole('button', { name: 'I Trusted This Device' }));
    expect(await screen.findByText('Device Paired')).toBeInTheDocument();
    await waitFor(() => expect(pairDeviceFlowMock).toHaveBeenCalledTimes(2));

    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(screen.queryByText('Device Paired')).toBeNull();
  });
});

describe('App — login modal', () => {
  it('opens login modal on Add Account, then logs in and navigates to sign', async () => {
    render(<App />);

    // Click Add Account to open modal
    await userEvent.click(screen.getByRole('button', { name: 'Add Account' }));
    expect(screen.getByText('Add Account', { selector: 'h2' })).toBeInTheDocument();

    // Fill form
    await userEvent.type(screen.getByLabelText('Apple ID'), 'user@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'secret');

    // Sign In
    await userEvent.click(screen.getByRole('button', { name: 'Sign In' }));
    await waitFor(() => expect(loginAccountMock).toHaveBeenCalled());

    // Navigates to sign page after login
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign & Install/ })).toBeInTheDocument());
  });

  it('shows 2FA modal when login flow requests a code', async () => {
    let resolveLogin: (ctx: AppleDeveloperContext) => void = () => {};
    loginAccountMock.mockImplementationOnce(async (req) => {
      req.onTwoFactorRequired({
        submitDeviceCode: (code) => {
          if (code === '123456') resolveLogin(fakeContext);
        },
        trustedPhoneNumbers: [],
        requestSms: async () => {},
        submitSmsCode: async () => {},
      });
      return await new Promise<AppleDeveloperContext>((resolve) => {
        resolveLogin = resolve;
      });
    });

    render(<App />);
    await userEvent.click(screen.getByRole('button', { name: 'Add Account' }));
    await userEvent.type(screen.getByLabelText('Apple ID'), 'u@e.com');
    await userEvent.type(screen.getByLabelText('Password'), 'pw');
    await userEvent.click(screen.getByRole('button', { name: 'Sign In' }));

    const code = await screen.findByLabelText('Verification Code');
    await userEvent.type(code, '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));

    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign & Install/ })).toBeInTheDocument());
  });
});


describe('App — saved accounts rehydration', () => {
  it('loads stored session and shows Active in accounts list', async () => {
    window.localStorage.setItem(
      'webmuxd:apple-account-summary',
      JSON.stringify({
        appleId: 'stored@e.com',
        teamId: 'T1',
        teamName: 'Stored Team',
        updatedAtIso: '2024-01-01T00:00:00.000Z',
      }),
    );
    window.localStorage.setItem(
      'webmuxd:apple-account-list',
      JSON.stringify([
        {
          appleId: 'stored@e.com',
          teamId: 'T1',
          teamName: 'Stored Team',
          updatedAtIso: '2024-01-01T00:00:00.000Z',
        },
      ]),
    );
    window.localStorage.setItem(
      'webmuxd:apple-account-session-map',
      JSON.stringify({
        'stored@e.com::T1': {
          appleId: 'stored@e.com',
          teamId: 'T1',
          teamName: 'Stored Team',
          dsid: 'd',
          authToken: 't',
          anisetteData: {
            machineID: 'MID',
            oneTimePassword: 'OTP',
            localUserID: 'LUID',
            routingInfo: 17106176,
            deviceUniqueIdentifier: 'DUI',
            deviceDescription: 'desc',
            deviceSerialNumber: '0',
            dateIso: '2024-01-01T00:00:00.000Z',
            locale: 'en_US',
            timeZone: 'UTC',
          },
          updatedAtIso: '2024-01-01T00:00:00.000Z',
        },
      }),
    );

    render(<App />);
    // Active label appears for the restored session
    expect(await screen.findByText('Active')).toBeInTheDocument();
    expect(screen.getByText('stored@e.com')).toBeInTheDocument();
  });
});

describe('App — delete account', () => {
  it('removes an account from the list when delete is clicked', async () => {
    window.localStorage.setItem(
      'webmuxd:apple-account-list',
      JSON.stringify([{ appleId: 'a@e.com', teamId: 'T1', teamName: 'A', updatedAtIso: '2024-01-01' }]),
    );

    render(<App />);
    const deleteBtn = await screen.findByTitle('Remove account');
    await userEvent.click(deleteBtn);
    expect(screen.getByText('No accounts yet.')).toBeInTheDocument();
  });
});
