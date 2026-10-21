// The change-password dialog filed a server 422 for an empty Current field as
// a form-level line under Confirm ("current_password is empty. Send a
// value."), and a change to the same password went through (dogfood
// 2026-10-19, H1-D4, H1-D16).
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  changePassword: vi.fn(),
}));
vi.mock('../lib/toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('../lib/useModalSurface', () => ({ useModalSurface: () => undefined }));

import { ApiError, changePassword } from '../lib/api';
import { ChangePasswordModal } from './ChangePasswordModal';

function fill(current: string, next: string, confirm: string) {
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: current } });
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: next } });
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: confirm } });
  fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
}

describe('ChangePasswordModal field checks', () => {
  it('asks for the current password under its own field', () => {
    render(<ChangePasswordModal open onClose={() => {}} />);
    fill('', 'a-new-password', 'a-new-password');
    const current = screen.getByLabelText('Current password');
    expect(current).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('Enter your current password.')).toBeInTheDocument();
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('refuses a new password that equals the current one', () => {
    render(<ChangePasswordModal open onClose={() => {}} />);
    fill('same-password', 'same-password', 'same-password');
    expect(screen.getByLabelText('New password')).toHaveAttribute('aria-invalid', 'true');
    expect(
      screen.getByText('The new password is the same as the current password. Enter a different password.'),
    ).toBeInTheDocument();
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('files the server refusal of an unchanged password under New password', async () => {
    vi.mocked(changePassword).mockRejectedValueOnce(
      new ApiError('The new password is the same as the current password.', 400, 'password_unchanged'),
    );
    render(<ChangePasswordModal open onClose={() => {}} />);
    // Different text that the server still treats as the same: the client
    // check passes, the server refuses.
    fill('current-pw-1', 'current-pw-2', 'current-pw-2');
    await screen.findByText('The new password is the same as the current password.');
    expect(screen.getByLabelText('New password')).toHaveAttribute('aria-invalid', 'true');
  });
});
