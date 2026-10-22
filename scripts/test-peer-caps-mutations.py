"""Disable the 40 L4 bounds plus round-2 guards, one at a time.

Run from the repository root. Logs go to /tmp/peer-caps-mutations-round2.
A mutant only counts as killed on a test assertion failure, never a build error.
Sources are restored in finally; do not run concurrently with edits/builds.
"""
from pathlib import Path
import argparse, os, re, subprocess, sys
wire = Path('crates/konsensus-message/src/wire.rs')
envelope = Path('crates/konsensus-message/src/wire/bounded_envelope.rs')
helper = Path('crates/konsensus-core/src/wire_json/strings.rs')
logging = Path('crates/konsensus-message/src/transport/messaging.rs')
scanner = Path('crates/konsensus-core/src/wire_json.rs')
originals = {p:p.read_text() for p in [wire, envelope, helper, logging, scanner]}
regression_dir = Path('crates/konsensus-message/tests')
regressions = {p: p.read_bytes() for p in regression_dir.glob('*.proptest-regressions')}
mutations=[]
s=originals[wire]
# Tests are behavioral: each hook is actually removed, not merely inspected.
pattern=r'#\[serde\(\s*(?:default,\s*)?deserialize_with = "bounded::limited_(?:opt_)?string::<_, [^>]+>"\s*\)\]'
for i,m in enumerate(re.finditer(pattern,s)):
 prefix=s[:m.start()]
 if 'pub enum Frame' not in prefix:
  continue
 if 'pub struct PeerExchangeQuote' in prefix:
  name='quote.bolt11';args=['--test','peer_frame_caps','quote_bolt11']
 else:
  variant=list(re.finditer(r'^    (\w+) \{', prefix, re.M))[-1].group(1)
  field=re.search(r'(\w+):',s[m.end():]).group(1)
  name=variant+'.'+field
  if variant.startswith('Starter') or variant=='LightningInfo':args=['--test','starter_wire']
  elif variant.startswith('PorchQuote'):args=['--lib','porch_quote_bounds_tests']
  else:
   test=re.sub(r'(?<!^)(?=[A-Z])','_',variant).lower()+'_'+field
   args=['--test','peer_frame_caps',test]
 mutations.append((name,wire,s[:m.start()]+s[m.end():],args))
# Tuple-variant hook is in Capability, before Frame.
custom='#[serde(deserialize_with = "bounded::limited_string::<_, MAX_CUSTOM_CAPABILITY_BYTES>")]'
mutations.append(('Capability.Custom',wire,s.replace(custom,'',1),['--test','peer_frame_caps','custom_capability']))
for name,old,new,test in [
 ('PriceTable.key','map.next_entry::<LimitedString<MAX_PRICE_KEY_BYTES>, u64>()?','map.next_entry::<LimitedString<MAX_FRAME_BYTES>, u64>()?','price_table_keys'),
 ('JSON.key','map.next_key::<LimitedString<MAX_JSON_KEY_BYTES>>()?','map.next_key::<LimitedString<MAX_FRAME_BYTES>>()?','prekey_and_session_json_keys'),
 ('JSON.string','limited_string::<_, MAX_JSON_STRING_BYTES>','limited_string::<_, MAX_FRAME_BYTES>','json_string'),
]:
 assert old in s
 mutations.append((name,wire,s.replace(old,new),['--test','peer_frame_caps',test]))
# Wire adapters now own these four bounds so generic core serde stays usable.
mutations.append(('Envelope.ciphertext', envelope, originals[envelope].replace(
    '#[serde(deserialize_with = "bounded::vec_u8::<_, MAX_CIPHERTEXT_BYTES>")]', ''),
    ['--test','peer_frame_caps','envelope_ciphertext']))
for n in [24, 32, 64]:
 start=s.index(f'    pub fn hex_{n}')
 end=s.index('\n    }', start)
 part=s[start:end]
 part=re.sub(r'bounded_json::string_value::<D, T, \d+>\(deserializer\)',
             'T::deserialize(deserializer)', part)
 mutations.append((f'fixed_hex.{n}', wire, s[:start]+part+s[end:],
                   ['--test','peer_fixed_hex_alloc']))
assert len(mutations) == 40, len(mutations)

def change(name, path, old, new, args):
 src=originals[path]
 assert old in src, name
 mutations.append((name, path, src.replace(old,new,1), args))
alloc=['--test','bounded_string_allocations']
change('pre_copy.string', helper,
       'check_string_bytes(raw.get(), max).map_err(de::Error::custom)?;',
       'let value: String = serde_json::from_str(raw.get()).map_err(de::Error::custom)?; if value.len() > max { return Err(de::Error::custom("over cap")); }', alloc)
change('pre_copy.typed_hex', helper,
       'check_string_bytes(raw.get(), MAX).map_err(de::Error::custom)?;',
       'let value: String = serde_json::from_str(raw.get()).map_err(de::Error::custom)?; if value.len() > MAX { return Err(de::Error::custom("over cap")); }',
       ['--test','peer_fixed_hex_alloc'])
change('enum.root', wire,
       'bounded_json::check_enum_tag(raw)',
       'Ok::<(), &str>(())', alloc+['unknown_variant_tags'])
change('enum.nested', helper,
       'check_enum_tag(raw.get()).map_err(de::Error::custom)?;', '', alloc+['unknown_variant_tags'])
change('enum.decoded_bytes', helper,
       'check_string_bytes(&tag[..=i], MAX_ENUM_TAG_BYTES)',
       'check_string_bytes(&tag[..=i], tag.len())', alloc+['unknown_variant_tags'])
change('JSON.nested_pre_copy', wire,
       'bounded_value_inner(deserializer, self.counter, self.depth_remaining)',
       'deserializer.deserialize_any(ValueVisitor { counter: self.counter, depth_remaining: self.depth_remaining })', alloc+['l4_escaped_strings'])
for occurrence, label in [(0,'ban'),(1,'budget')]:
 src=originals[logging]
 positions=[m.start() for m in re.finditer(re.escape('error = error.log_category()'),src)]
 assert len(positions)==2
 start=positions[occurrence]
 mutant=src[:start]+src[start:].replace('error = error.log_category()', 'error = %error',1)
 mutations.append((f'log.{label}',logging,mutant,['--lib','invalid_frame_warnings_never_echo_peer_bytes']))
change('typed.Room', envelope,
       '#[serde(deserialize_with = "bounded_json::string_value::<_, _, 45>")]', '', alloc+['typed_text_fields'])
change('typed.optional_uuid', wire,
       '#[serde(default, deserialize_with = "bounded::optional_uuid")]', '', alloc+['typed_text_fields'])
change('typed.socket_addr', wire,
       '#[serde(deserialize_with = "bounded::parsed_string::<_, _, 64>")]', '', alloc+['typed_text_fields'])
change('typed.required_uuid', wire,
       '#[serde(deserialize_with = "bounded::parsed_string::<_, _, 45>")]', '', alloc+['typed_text_fields'])
change('bytes.wrong_array_type', helper,
       "if !raw.get().starts_with('[') {", "if false {", alloc+['wrong_type_byte_arrays'])
change('bytes.wrong_element_type', helper,
       "if !matches!(raw.get().as_bytes().first(), Some(b'0'..=b'9')) {", "if false {", alloc+['wrong_type_byte_arrays'])
change('enum.exact_limit', helper,
       'check_string_bytes(&tag[..=i], MAX_ENUM_TAG_BYTES)',
       'check_string_bytes(&tag[..=i], MAX_ENUM_TAG_BYTES - 1)', ['--lib','enum_tag_bound_counts_decoded_bytes'])
change('frame.raw_string_ceiling', scanner,
       'if i - begin > limit.map_or(MAX_RAW_STRING_TOKEN_BYTES, |n: usize| n.saturating_mul(6))\n            {',
       'if false {', alloc+['global_string_ceiling_rejects'])
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--only', help='Run mutations whose names contain this text')
selected = parser.parse_args().only
if selected:
 mutations = [m for m in mutations if selected in m[0]]
 assert mutations, f'No mutations match {selected!r}'
env=os.environ.copy();env.update(CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
logs=Path('/private/tmp/peer-caps-mutations-round2');logs.mkdir(exist_ok=True)
try:
 for i,(name,path,mutant,args) in enumerate(mutations,1):
  assert mutant != originals[path],name
  path.write_text(mutant)
  result=subprocess.run(['cargo','test','--locked','-p','konsensus-message',*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  path.write_text(originals[path])
  (logs/f'{i:02d}-{name}.log').write_text(result.stdout)
  killed=result.returncode!=0 and 'test result: FAILED' in result.stdout
  print(f'{i}/{len(mutations)} {name}: '+('KILLED' if killed else 'SURVIVED/ERROR'),flush=True)
  if not killed:
   print(result.stdout[-3000:]);sys.exit(1)
finally:
 for path,original in originals.items(): path.write_text(original)
 for path in regression_dir.glob('*.proptest-regressions'):
  if path in regressions: path.write_bytes(regressions[path])
  else: path.unlink()
print(f'All {len(mutations)} mutations killed; source restored.',flush=True)
