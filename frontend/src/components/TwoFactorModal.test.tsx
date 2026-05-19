import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { TwoFactorContext } from '../apple-signing';
import { TwoFactorModal } from './TwoFactorModal';

function createTwoFactorContext(overrides: Partial<TwoFactorContext> = {}): TwoFactorContext {
  return {
    submitDeviceCode: vi.fn(),
    trustedPhoneNumbers: [],
    requestSms: vi.fn(),
    submitSmsCode: vi.fn(),
    ...overrides,
  };
}

describe('TwoFactorModal', () => {
  it('is hidden when closed', () => {
    const { container } = render(<TwoFactorModal open={false} ctx={null} onCancel={() => {}} />);
    expect(container.querySelector('.modal')).not.toHaveClass('open');
  });

  it('focuses the input when opened', async () => {
    render(<TwoFactorModal open ctx={createTwoFactorContext()} onCancel={() => {}} />);
    // useEffect runs a setTimeout(0) before focusing — let it tick.
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(screen.getByLabelText('Verification Code')).toHaveFocus();
  });

  it('shows an inline error when submitting an empty code', async () => {
    const ctx = createTwoFactorContext();
    render(<TwoFactorModal open ctx={ctx} onCancel={() => {}} />);
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(screen.getByText('Please enter the verification code.')).toBeInTheDocument();
    expect(ctx.submitDeviceCode).not.toHaveBeenCalled();
  });

  it('clears the error once the user starts typing', async () => {
    render(<TwoFactorModal open ctx={createTwoFactorContext()} onCancel={() => {}} />);
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(screen.getByText('Please enter the verification code.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Verification Code'), '1');
    expect(screen.queryByText('Please enter the verification code.')).not.toBeInTheDocument();
  });

  it('submits a trimmed code on Enter', async () => {
    const ctx = createTwoFactorContext();
    render(<TwoFactorModal open ctx={ctx} onCancel={() => {}} />);
    const input = screen.getByLabelText('Verification Code');
    await userEvent.type(input, '  123456  ');
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(ctx.submitDeviceCode).toHaveBeenLastCalledWith('123456');
  });

  it('submits via the Verify button', async () => {
    const ctx = createTwoFactorContext();
    render(<TwoFactorModal open ctx={ctx} onCancel={() => {}} />);
    await userEvent.type(screen.getByLabelText('Verification Code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(ctx.submitDeviceCode).toHaveBeenLastCalledWith('654321');
  });

  it('calls onCancel when Cancel is clicked', async () => {
    const onCancel = vi.fn();
    render(<TwoFactorModal open ctx={createTwoFactorContext()} onCancel={onCancel} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
