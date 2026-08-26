import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SignPage } from './SignPage';

type Props = Parameters<typeof SignPage>[0];

function defaultProps(overrides: Partial<Props> = {}): Props {
  const noop = () => {};
  return {
    file: null,
    onFileChange: noop,
    accounts: [],
    activeAccountKey: null,
    onAccountChange: noop,
    knownUdids: [],
    connectedUdid: null,
    selectedUdid: '',
    onSelectedUdidChange: noop,
    onPair: noop,
    pairBusy: false,
    pairDisabled: false,
    onSign: noop,
    signBusy: false,
    signDisabled: true,
    onInstall: noop,
    installBusy: false,
    installDisabled: true,
    ...overrides,
  };
}

describe('SignPage', () => {
  it('renders local signing, account signing, device controls and action buttons', () => {
    render(
      <SignPage
        {...defaultProps({
          accounts: [{ appleId: 'u@e.com', teamId: 'T1', teamName: 'Team', updatedAtIso: '2024-01-01' }],
        })}
      />,
    );
    expect(screen.getByRole('heading', { name: /Sign & Install/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Local certificate signing' })).toBeInTheDocument();
    expect(screen.getByLabelText('P12 certificate')).toBeInTheDocument();
    expect(screen.getByLabelText('Provisioning profile')).toBeInTheDocument();
    expect(screen.getByLabelText('P12 password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign & Download Locally' })).toBeDisabled();
    expect(screen.getByLabelText('Apple Signing Account')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect Device' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign IPA' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Install Signed IPA' })).toBeInTheDocument();
  });

  it('propagates sign / install clicks when enabled', async () => {
    const onSign = vi.fn();
    const onInstall = vi.fn();
    render(
      <SignPage
        {...defaultProps({
          onSign,
          onInstall,
          signDisabled: false,
          installDisabled: false,
        })}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Sign IPA' }));
    expect(onSign).toHaveBeenCalled();

    await userEvent.click(screen.getByRole('button', { name: 'Install Signed IPA' }));
    expect(onInstall).toHaveBeenCalled();
  });
});
