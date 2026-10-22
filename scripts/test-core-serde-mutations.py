#!/usr/bin/env python3
"""Mutation check for peer payload boundaries; restores sources even on failure.
Run alone (no concurrent build/editor). Logs are retained in a unique temporary
directory printed at startup.
Only an assertion/test failure kills a mutant; compilation failures do not.
"""
from pathlib import Path
import argparse
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--only')
selected = parser.parse_args().only
core = Path('crates/konsensus-core/src/wire_json.rs')
strings = Path('crates/konsensus-core/src/wire_json/strings.rs')
wire = Path('crates/konsensus-message/src/wire.rs')
relay = Path('crates/konsensus-node/src/relay/dispatch.rs')
room = Path('crates/konsensus-core/src/payloads/room.rs')
originals = {p: p.read_text() for p in (core, strings, wire, relay, room)}
mutants = []

def add(name, path, old, new, package, *args):
    assert originals[path].count(old) == 1, name
    mutants.append((name, path, originals[path].replace(old, new), package, args))

add('raw-token-preflight', core,
    'check_payload(data, fields).map_err(|_| DecodeError)?;', '',
    'konsensus-node', '--bin', 'konsensus', 'relay_body_decodes_reject_before_large_allocations')
add('standalone-envelope-adapter', wire,
    'konsensus_core::wire_json::from_slice::<Envelope>(data).map(|envelope| *envelope.0)',
    'konsensus_core::wire_json::from_slice::<UkmEnvelope>(data)',
    'konsensus-message', '--test', 'standalone_envelope_allocations', 'relay_envelope_uses_frame_field_bounds')
add('pre-copy-string-bound', strings,
    'check_string_bytes(raw.get(), MAX).map_err(de::Error::custom)?;', '',
    'konsensus-message', '--test', 'standalone_envelope_allocations', 'relay_envelope_uses_frame_field_bounds')
add('deposit-body-entry', relay,
    'let body: DepositBody = match wire_json::from_slice(&envelope.ciphertext)',
    'let body: DepositBody = match serde_json::from_slice(&envelope.ciphertext)',
    'konsensus-node', '--bin', 'konsensus', 'relay_body_decodes_reject_before_large_allocations')
add('drain-body-entry', relay,
    'let body: DrainBody = match wire_json::from_slice(&envelope.ciphertext)',
    'let body: DrainBody = match serde_json::from_slice(&envelope.ciphertext)',
    'konsensus-node', '--bin', 'konsensus', 'relay_body_decodes_reject_before_large_allocations')
add('deposit-envelope-entry', relay,
    'match envelope_from_bytes(&body.inner_envelope_bytes)',
    'match serde_json::from_slice(&body.inner_envelope_bytes)',
    'konsensus-node', '--bin', 'konsensus', 'relay_deposit_and_held_mail_use_standalone_envelope_admission')
add('held-envelope-entry', relay,
    'match envelope_from_bytes(&item.envelope_bytes)',
    'match serde_json::from_slice(&item.envelope_bytes)',
    'konsensus-node', '--bin', 'konsensus', 'relay_deposit_and_held_mail_use_standalone_envelope_admission')
add('large-field-decoded-bound', core,
    'strings::check_string_bytes(raw, max)?;', 'let _ = (raw, max);',
    'konsensus-core', '--test', 'wire_json_allocations', 'payload_exceptions_cannot_relax')

add('unfinished-large-string', core,
    'if start.is_some() {', 'if false {',
    'konsensus-core', '--test', 'wire_json_allocations', 'unterminated_large_body')
add('room-admission-fail-closed', room,
    'crate::wire_json::check_payload(plaintext.as_bytes(), &[])',
    'Ok::<(), &str>(())',
    'konsensus-core', '--test', 'wire_json_allocations', 'oversized_room_chat')

# Regressions for the #370 review's surviving defence-in-depth mutants.
add('ack-sequence-guard', relay,
    'konsensus_core::wire_json::strings::sequence(deserializer, AckIdVisitor)',
    'deserializer.deserialize_seq(AckIdVisitor)',
    'konsensus-node', '--bin', 'konsensus', 'ack_under_cap_strings')
add('ack-element-guard', relay,
    'struct Id(#[serde(deserialize_with = "bounded::hex_32")] MessageId);',
    'struct Id(MessageId);',
    'konsensus-node', '--bin', 'konsensus', 'ack_under_cap_strings')
add('register-binding-id-bound', relay,
    '#[serde(deserialize_with = "bounded::vec_u8::<_, 16>")]\n    binding_id:',
    'binding_id:',
    'konsensus-node', '--bin', 'konsensus', 'register_binding_id_rejects_seventeen_bytes')
add('large-field-top-level-only', core,
    'if depth == 1\n                    && data[i + 1..]',
    'if data[i + 1..]',
    'konsensus-api', '--test', 'file_wire_decode', 'file_exception_rejects_nested_unknown_key')

if selected:
    mutants = [m for m in mutants if selected in m[0]]
    assert mutants, selected
logs = Path(tempfile.mkdtemp(prefix='core-serde-mutations-'))
print(f'Logs: {logs}', flush=True)
try:
    for name, path, mutant, package, args in mutants:
        path.write_text(mutant)
        result = subprocess.run(['cargo', 'test', '--locked', '-p', package, *args],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        path.write_text(originals[path])
        (logs / f'{name}.log').write_text(result.stdout)
        killed = result.returncode != 0 and 'test result: FAILED' in result.stdout
        print(f'{name}: {"KILLED" if killed else "SURVIVED/BUILD ERROR"}', flush=True)
        if not killed:
            raise SystemExit(result.stdout[-4000:])
finally:
    for path, original in originals.items():
        path.write_text(original)
print(f'All {len(mutants)} mutants killed by tests; sources restored.', flush=True)
