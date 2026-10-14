"""Bounded native verification of an exact draft package, not a campaign worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import struct
import shutil
import subprocess
import tarfile
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--os', required=True)
parser.add_argument('--arch', required=True)
parser.add_argument('--out', required=True)
args = parser.parse_args()
assert os.environ.get('HOWL_FORBID_LOCAL_INFERENCE') == '1'
actual_os = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}[platform.system()]
actual_arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'ARM64': 'arm64'}[platform.machine()]
assert (actual_os, actual_arch) == (args.os, args.arch), (actual_os, actual_arch)
manifest = json.loads(Path(__file__).with_name('native_manifest.json').read_text())
contract = manifest['platforms'][args.os + '-' + args.arch]
out = Path(args.out).resolve()
out.mkdir(parents=True, exist_ok=False)
records = []

def command(argv, cwd=None, env=None, expected=0, label=None):
    result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env,
                            text=True, capture_output=True, timeout=180)
    records.append({'argv': [str(a) for a in argv], 'exit_code': result.returncode,
                    'stdout': result.stdout, 'stderr': result.stderr})
    (out / 'commands.json').write_text(json.dumps(records, indent=2))
    if label:
        (out / (label + '.stdout.log')).write_text(result.stdout)
        (out / (label + '.stderr.log')).write_text(result.stderr)
    if expected == 'nonzero':
        assert result.returncode != 0, result.stdout
    else:
        assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return result


def download(repo, name, target):
    target.mkdir()
    command(['gh', 'release', 'download', 'v0.1.0', '--repo', repo,
             '--pattern', name, '--dir', target])
    return target / name


def extract(archive, target, expected_hash, expected_files=None):
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected_hash
    target.mkdir()
    found = set()
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as source:
            entries = [(i.filename, not i.is_dir(), stat.S_IFMT(i.external_attr >> 16) != stat.S_IFLNK,
                        source.read(i) if not i.is_dir() else b'') for i in source.infolist()]
    else:
        with tarfile.open(archive) as source:
            entries = [(i.name, not i.isdir(), i.isfile() or i.isdir(),
                        source.extractfile(i).read() if i.isfile() else b'') for i in source.getmembers()]
    for name, is_file, regular, data in entries:
        assert '\\' not in name and ':' not in name, name
        parts = PurePosixPath(name)
        assert not parts.is_absolute() and '..' not in parts.parts
        assert regular, name
        if not is_file:
            continue
        relative = Path(*parts.parts)
        destination = target / relative
        assert destination.resolve().is_relative_to(target.resolve()), name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o755)
        found.add(relative.name)
        if expected_files:
            assert relative.name in expected_files
            assert hashlib.sha256(data).hexdigest() == expected_files[relative.name]
    if expected_files:
        assert found == set(expected_files)


package = download('howlcipher/howlchangeops', contract['archive'], out / 'package-download')
frame_package = download('howlcipher/howlframe', contract['frame_archive'], out / 'frame-download')
# Download credentials must never reach package execution or fixture subprocesses.
for key in list(os.environ):
    if 'TOKEN' in key.upper() or key.upper().endswith(('PASSWORD', 'SECRET')):
        os.environ.pop(key)
extract(package, out / 'package', contract['sha256'], contract['files'])
extract(frame_package, out / 'frame', contract['frame_sha256'])
exe = '.exe' if args.os == 'windows' else ''
adapter = out / 'package' / ('howlchangeops' + exe)
alias = out / 'package' / ('changeops' + exe)
frame = out / 'frame' / ('howlframe' + exe)
assert hashlib.sha256(adapter.read_bytes()).digest() == hashlib.sha256(alias.read_bytes()).digest()
def header_arch(binary):
    data = binary.read_bytes()
    if args.os == 'linux':
        assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1
        return {62: 'amd64', 183: 'arm64'}[struct.unpack_from('<H', data, 18)[0]]
    if args.os == 'darwin':
        assert data[:4] == b'\xcf\xfa\xed\xfe'
        return {0x1000007: 'amd64', 0x100000c: 'arm64'}[struct.unpack_from('<I', data, 4)[0]]
    assert data[:2] == b'MZ'
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[offset:offset+4] == b'PE\x00\x00'
    return {0x8664: 'amd64', 0xaa64: 'arm64'}[struct.unpack_from('<H', data, offset+4)[0]]

hardware = {'process_arch': actual_arch}
if args.os == 'darwin':
    silicon = command(['sysctl', '-n', 'hw.optional.arm64']).stdout.strip()
    assert silicon == ('1' if args.arch == 'arm64' else '0'), silicon
    hardware['apple_silicon'] = silicon == '1'
if args.os == 'windows':
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(ctypes.c_ushort)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
    assert kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine))
    assert process_machine.value == 0 and native_machine.value == 0x8664
    hardware.update(process_machine=process_machine.value, native_machine=native_machine.value)
real_go = Path(shutil.which('go')).resolve()
binary_metadata = {}
for binary in [adapter, alias, frame]:
    assert header_arch(binary) == args.arch
    info = command([real_go, 'version', '-m', binary]).stdout
    assert re.search(r'build\s+GOOS=' + re.escape(args.os) + r'\s*$', info, re.M), info
    assert re.search(r'build\s+GOARCH=' + re.escape(args.arch) + r'\s*$', info, re.M), info
    binary_metadata[binary.name] = {'GOOS': args.os, 'GOARCH': args.arch, 'executable_header': args.arch}
    result = command([binary, '--version'])
    assert '0.1.0' in result.stdout
command([real_go, 'version'])
assert command([real_go, 'env', 'GOOS', 'GOARCH']).stdout.split() == [args.os, args.arch]
repo = out / 'fixture-repo'
repo.mkdir()
(repo / 'go.mod').write_text('module example.test/releaseprobe\n\ngo 1.21\n')
(repo / 'sum.go').write_text('package releaseprobe\nfunc Sum(a, b int) int { return a + b }\n')
test = repo / 'sum_test.go'
test.write_text('package releaseprobe\nimport "testing"\nfunc TestSum(t *testing.T) { if Sum(2,3) != 5 { t.Fatal("sum") } }\n')
command(['git', 'init', '-b', 'main'], cwd=repo)
command(['git', 'config', 'user.name', 'HOWL native package fixture'], cwd=repo)
command(['git', 'config', 'user.email', 'fixture@example.invalid'], cwd=repo)
command(['git', 'add', '.'], cwd=repo)
# This is an ephemeral test fixture, never a source repair or authority envelope.
command(['git', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture: passing Go validation'], cwd=repo)
caller = out / 'caller'
(caller / 'config').mkdir(parents=True)
config = {'repos': {'fixture': {'path': str(repo), 'validation_profile': 'go',
                              'allowed_branches': ['main'], 'allowed_actions': ['create_release_candidate']}},
          'require_security_scan': False}
(caller / 'config/howlchangeops-config.json').write_text(json.dumps(config))
proposal = caller / 'proposal.json'
proposal.write_text(json.dumps({'repo': 'fixture', 'action': 'create_release_candidate',
                                'reason': 'native package fixture', 'approved': True,
                                'admin': True, 'override': True, 'security_verified': True}))
env = os.environ.copy()
env['HOWLFRAME_BIN'] = str(frame)
env['HOWLCHANGEOPS_BASE'] = str(out / 'governance-state')
observer_dir = out / 'go-observer'
observer_dir.mkdir()
command([real_go, 'build', '-o', observer_dir / ('go' + exe), Path(__file__).with_name('go_observer.go')])
env['PATH'] = str(observer_dir) + os.pathsep + env['PATH']
env['HOWL_NATIVE_REAL_GO'] = str(real_go)
env['GOFLAGS'] = '-v'
env['HOWL_NATIVE_GO_LOG'] = str(out / 'package-valid-go-observations.jsonl')

def verify_observations(evidence, log_path, passing):
    observed = [json.loads(line) for line in log_path.read_text().splitlines()]
    tests = [item for item in observed if item['argv'] == ['test', './...']]
    builds = [item for item in observed if item['argv'] == ['build', './...']]
    assert len(tests) == len(builds) == 1, observed
    assert Path(tests[0]['cwd']).resolve() == repo
    assert '=== RUN   TestSum' in tests[0]['output']
    assert ('--- PASS: TestSum' if passing else 'intentional failure') in tests[0]['output']
    for name, observation in [('test', tests[0]), ('build', builds[0])]:
        check = evidence['checks'][name]
        assert check['exit_code'] == observation['exit_code']
        assert check['output_digest'] == hashlib.sha256(observation['output'].encode()).hexdigest()
    assert (tests[0]['exit_code'] == 0) == passing and builds[0]['exit_code'] == 0

def expect_decision(result, expected):
    decisions = [line.removeprefix('Decision: ') for line in result.stdout.splitlines() if line.startswith('Decision: ')]
    assert decisions == [expected], result.stdout

result = command([adapter, 'evaluate', proposal], cwd=caller, env=env, label='empty-evidence')
expect_decision(result, 'DENY')
direct = command([real_go, 'test', '-count=1', '-v', './...'], cwd=repo, env=env, label='direct-valid-go')
assert '=== RUN   TestSum' in direct.stdout and '--- PASS: TestSum' in direct.stdout
command([adapter, 'validate', 'fixture'], cwd=caller, env=env, label='valid-validation')
passing_revision = command(['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.strip()
passing = [json.loads(p.read_text()) for p in (out / 'governance-state').glob('evidence_*.json')]
passing = [item for item in passing if item['repo'] == 'fixture' and item['revision'] == passing_revision]
assert len(passing) == 1
assert all(passing[0]['checks'][name]['status'] == 'PASS' and passing[0]['checks'][name]['exit_code'] == 0 for name in ['test', 'build', 'working_tree'])
verify_observations(passing[0], out / 'package-valid-go-observations.jsonl', True)
result = command([adapter, 'evaluate', proposal], cwd=caller, env=env, label='valid-evaluation')
expect_decision(result, 'REQUIRE_APPROVAL')
# Current committed failing tests must produce fresh FAIL evidence and deny release.
test.write_text('package releaseprobe\nimport "testing"\nfunc TestSum(t *testing.T) { if Sum(2,3) != 99 { t.Fatal("intentional failure") } }\n')
command(['git', 'add', '.'], cwd=repo)
command(['git', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture: intentionally failing Go validation'], cwd=repo)
direct_failure = command([real_go, 'test', '-count=1', '-v', './...'], cwd=repo, env=env, expected='nonzero', label='direct-invalid-go')
assert '=== RUN   TestSum' in direct_failure.stdout and 'intentional failure' in direct_failure.stdout
env['HOWL_NATIVE_GO_LOG'] = str(out / 'package-invalid-go-observations.jsonl')
wrapper = command([adapter, 'validate', 'fixture'], cwd=caller, env=env, label='invalid-validation')
# The documented command records check outcomes; exit zero is not a PASS claim.
revision = command(['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.strip()
evidence = [json.loads(p.read_text()) for p in (out / 'governance-state').glob('evidence_*.json')]
failed = [item for item in evidence if item['repo'] == 'fixture' and item['revision'] == revision]
assert len(failed) == 1
assert failed[0]['checks']['test']['status'] == 'FAIL'
assert failed[0]['checks']['test']['exit_code'] != 0
assert failed[0]['checks']['build']['status'] == 'PASS'
verify_observations(failed[0], out / 'package-invalid-go-observations.jsonl', False)
(out / 'invalid-validation-evidence.json').write_text(json.dumps(failed[0], indent=2))
result = command([adapter, 'evaluate', proposal], cwd=caller, env=env, label='invalid-evaluation')
expect_decision(result, 'DENY')
report = {'os': actual_os, 'arch': actual_arch, 'host': platform.platform(),
          'source_sha': manifest['source_sha'], 'compiler_source_sha': manifest['compiler_source_sha'],
          'archive_sha256': contract['sha256'], 'frame_archive_sha256': contract['frame_sha256'],
          'native_execution': True, 'hardware_architecture': hardware, 'packaged_go_outputs_bound_to_checks': True, 'executable_goos_goarch_match': binary_metadata, 'alias_regular_identical_copy': True,
          'empty_evidence': 'DENY', 'valid_evidence': 'REQUIRE_APPROVAL',
          'actual_failing_validation': {'check': 'FAIL', 'test_exit_code': failed[0]['checks']['test']['exit_code'], 'recording_cli_exit_code': wrapper.returncode}, 'fresh_failing_evidence_decision': 'DENY',
          'approve_execute_performed': False, 'local_inference': False,
          'fixture_not_owner_approval': True, 'verdict': 'PASS'}
(out / 'verification.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
