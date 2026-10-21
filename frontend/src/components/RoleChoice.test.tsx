// One role vocabulary for every declare (dogfood 2026-10-19, R4-D20). The
// host page offered a free-text box with a datalist, and the Hosts bulk bar
// offered a closed list. Both now use one control: the vocabulary roles, and
// "Other" with a text box where a novel role is allowed.
import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { DossierField } from '../lib/types';
import { DeclareEditor } from './HostFacts';
import { OTHER_ROLE, RoleChoice } from './RoleChoice';

function roleField(over: Partial<DossierField> = {}): DossierField {
  return {
    field: 'role',
    value: null,
    value_json: null,
    source: null,
    confidence: 0,
    strength: 'none',
    reason: 'no_signal',
    overridden: false,
    conflict_kind: null,
    evidence: {},
    observed_at: null,
    first_seen: null,
    last_run_at: null,
    retracted_at: null,
    operator_actor: null,
    operator_note: null,
    operator_set_at: null,
    inferred_value: null,
    inferred_value_json: null,
    inferred_confidence: null,
    inferred_source: null,
    conflict: null,
    ...over,
  };
}

/** A parent that holds the value, as the bulk bar and the declare form do. */
function Harness({
  initial = '',
  allowOther,
  onValue,
}: {
  initial?: string;
  allowOther?: boolean;
  onValue?: (v: string) => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <RoleChoice
      value={value}
      onChange={(v) => {
        setValue(v);
        onValue?.(v);
      }}
      vocabulary={['workstation', 'server', 'domain_controller']}
      allowOther={allowOther}
      label="Role to declare"
    />
  );
}

const optionValues = (select: HTMLElement) =>
  Array.from((select as HTMLSelectElement).options).map((o) => o.value);
const optionLabels = (select: HTMLElement) =>
  Array.from((select as HTMLSelectElement).options).map((o) => o.textContent);

describe('RoleChoice', () => {
  it('lists the vocabulary roles in reading form, then Other', () => {
    render(<Harness />);
    const select = screen.getByLabelText('Role to declare');
    expect(optionValues(select)).toEqual(['', 'domain_controller', 'server', 'workstation', OTHER_ROLE]);
    expect(optionLabels(select)).toEqual(['choose', 'domain controller', 'server', 'workstation', 'Other']);
    expect(screen.queryByLabelText('Type the role')).toBeNull();
  });

  it('shows a text box for Other and passes the typed role up', () => {
    const onValue = vi.fn();
    render(<Harness onValue={onValue} />);
    fireEvent.change(screen.getByLabelText('Role to declare'), { target: { value: OTHER_ROLE } });
    const box = screen.getByLabelText('Type the role');
    expect(document.activeElement).toBe(box);
    fireEvent.change(box, { target: { value: 'jump host' } });
    expect(onValue).toHaveBeenLastCalledWith('jump host');
    // The list keeps Other selected while the box holds the role.
    expect((screen.getByLabelText('Role to declare') as HTMLSelectElement).value).toBe(OTHER_ROLE);
  });

  it('hides the text box again when a listed role is chosen', () => {
    const onValue = vi.fn();
    render(<Harness onValue={onValue} />);
    fireEvent.change(screen.getByLabelText('Role to declare'), { target: { value: OTHER_ROLE } });
    fireEvent.change(screen.getByLabelText('Type the role'), { target: { value: 'jump host' } });
    fireEvent.change(screen.getByLabelText('Role to declare'), { target: { value: 'server' } });
    expect(onValue).toHaveBeenLastCalledWith('server');
    expect(screen.queryByLabelText('Type the role')).toBeNull();
  });

  it('opens on Other with the text when the value is not in the vocabulary', () => {
    render(<Harness initial="jump host" />);
    expect((screen.getByLabelText('Role to declare') as HTMLSelectElement).value).toBe(OTHER_ROLE);
    expect((screen.getByLabelText('Type the role') as HTMLInputElement).value).toBe('jump host');
  });

  it('offers no Other when the caller allows only the vocabulary', () => {
    // NEGATIVE CONTROL: the bulk bar. The server refuses a novel role there.
    render(<Harness allowOther={false} />);
    expect(optionValues(screen.getByLabelText('Role to declare'))).toEqual([
      '',
      'domain_controller',
      'server',
      'workstation',
    ]);
  });
});

describe('DeclareEditor: the role value', () => {
  const mountEditor = (f: DossierField, extra: { roleVocabulary?: readonly string[] } = {}) => {
    const onSave = vi.fn();
    const onInvalid = vi.fn();
    render(
      <DeclareEditor
        f={f}
        busy={false}
        onSave={onSave}
        onCancel={() => {}}
        onInvalid={onInvalid}
        {...extra}
      />,
    );
    return { onSave, onInvalid };
  };

  it('offers the role list with Other, and starts on the inferred role', () => {
    mountEditor(roleField({ inferred_value: 'server' }));
    const select = screen.getByLabelText('Value for Role') as HTMLSelectElement;
    expect(select.tagName).toBe('SELECT');
    expect(select.value).toBe('server');
    expect(optionValues(select)).toContain('domain_controller');
    expect(optionValues(select)).toContain('hypervisor');
    const values = optionValues(select);
    expect(values[values.length - 1]).toBe(OTHER_ROLE);
    // The form label still names the control.
    expect(screen.getByText('Value').getAttribute('for')).toBe(select.id);
  });

  it('reads the vocabulary from the roleVocabulary prop', () => {
    mountEditor(roleField(), { roleVocabulary: ['printer', 'server'] });
    expect(optionValues(screen.getByLabelText('Value for Role'))).toEqual(['', 'printer', 'server', OTHER_ROLE]);
  });

  it('saves a listed role', () => {
    const { onSave } = mountEditor(roleField({ inferred_value: 'server' }));
    fireEvent.change(screen.getByLabelText('Value for Role'), { target: { value: 'hypervisor' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(onSave).toHaveBeenCalledWith({ field: 'role', value: 'hypervisor' });
  });

  it('saves a trimmed Other role', () => {
    const { onSave } = mountEditor(roleField({ inferred_value: 'server' }));
    fireEvent.change(screen.getByLabelText('Value for Role'), { target: { value: OTHER_ROLE } });
    fireEvent.change(screen.getByLabelText('Type the role'), { target: { value: '  jump host  ' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(onSave).toHaveBeenCalledWith({ field: 'role', value: 'jump host' });
  });

  it('refuses an empty Other role', () => {
    const { onSave, onInvalid } = mountEditor(roleField({ inferred_value: 'server' }));
    fireEvent.change(screen.getByLabelText('Value for Role'), { target: { value: OTHER_ROLE } });
    fireEvent.change(screen.getByLabelText('Type the role'), { target: { value: '   ' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(onInvalid).toHaveBeenCalledWith('A declaration needs a value.');
  });

  it('opens a declared novel role on Other with its text', () => {
    mountEditor(roleField({ value: 'jump host', overridden: true, source: 'operator' }));
    expect((screen.getByLabelText('Value for Role') as HTMLSelectElement).value).toBe(OTHER_ROLE);
    expect((screen.getByLabelText('Type the role') as HTMLInputElement).value).toBe('jump host');
  });

  it('keeps a plain text box on any other scalar fact', () => {
    // NEGATIVE CONTROL
    mountEditor({ ...roleField(), field: 'hostname' });
    expect(screen.getByLabelText('Value for Hostname').tagName).toBe('INPUT');
    expect(screen.queryByLabelText('Type the role')).toBeNull();
  });
});
