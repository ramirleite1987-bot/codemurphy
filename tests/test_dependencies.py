import base64
import json
import unittest

from codemurphy.dependencies import DependencyError, audit, delta, pinned_lockfiles, public_releases


def integrity(byte):
    return 'sha512-' + base64.b64encode(bytes([byte]) * 64).decode()


def lock(rows):
    body = {key: {'resolution': value if isinstance(value, dict) else {'integrity': value}}
            for key, value in rows.items()}
    return json.dumps({'lockfileVersion': '9.0', 'packages': body}).encode()


def registry(name, version, sri, tarball=None):
    return {'name': name, 'versions': {version: {'name': name, 'version': version, 'dist': {
        'integrity': sri, 'tarball': tarball or f'https://registry.npmjs.org/{name}/-/{name.split("/")[-1]}-{version}.tgz',
    }}}}


class DependencyTests(unittest.TestCase):
    def test_only_verified_changed_artifacts_can_leave_the_runner(self):
        unchanged = {'stable@1.0.0': integrity(1), 'pkg@1.0.0': integrity(2), 'removed@1.0.0': integrity(3)}
        head = lock({'stable@1.0.0': integrity(1), 'pkg@1.2.0': integrity(4),
                     '@public/new@2.0.0': integrity(5), '@private/payroll@1.0.0': integrity(6),
                     'wrong-sri@1.0.0': integrity(7),
                     'linked@file:../finance': integrity(8), 'custom@1.0.0': {
                         'integrity': integrity(9), 'tarball': 'https://internal.invalid/a.tgz'}})
        verified, rejected = public_releases(delta(lock(unchanged), head),
            {'stable', 'removed', 'pkg', '@public/new', 'wrong-sri', 'linked', 'custom'},
            lambda name: {
                'pkg': registry('pkg', '1.2.0', integrity(4)),
                '@public/new': registry('@public/new', '2.0.0', integrity(5)),
                'wrong-sri': registry('wrong-sri', '1.0.0', integrity(0)),
            }[name])
        self.assertEqual(verified, {('pkg', '1.2.0'), ('@public/new', '2.0.0')})
        self.assertEqual(rejected, {'unapproved_name': 1, 'unsupported_resolution': 2, 'integrity_mismatch': 1})

    def test_replaced_content_requires_matching_public_artifact_even_with_same_version(self):
        changed = delta(lock({'pkg@1.0.0': integrity(0)}), lock({'pkg@1.0.0': integrity(1)}))
        self.assertEqual(public_releases(changed, {'pkg'}, lambda _: registry('pkg', '1.0.0', integrity(0))),
                         (set(), {'integrity_mismatch': 1}))

    def test_explicit_public_tarball_with_same_integrity_is_not_a_new_artifact(self):
        implicit = lock({'pkg@1.0.0': integrity(0)})
        explicit = lock({'pkg@1.0.0': {'integrity': integrity(0),
                                      'tarball': 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz'}})
        self.assertEqual(delta(implicit, explicit), {})
        self.assertEqual(delta(explicit, implicit), {})

    def test_rejects_aliases_duplicate_keys_and_wrong_lockfile_version(self):
        bad = [b'lockfileVersion: "8.0"\npackages: {}',
               b'lockfileVersion: "9.0"\npackages: &foo {}\nsnapshots: *foo',
               b'lockfileVersion: "9.0"\npackages:\n  a@1.0.0: {}\n  a@1.0.0: {}\n']
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(DependencyError):
                delta(lock({}), raw)

    def test_audit_never_calls_socket_or_osv_with_no_eligible_public_releases(self):
        def unexpected(*args):
            self.fail('Unverified packages cannot trigger lookups or scanning')
        report = audit(lock({}), lock({'@private/payroll@1.0.0': integrity(1)}), {'public'},
                       npm=unexpected, socket=unexpected, osv=unexpected)
        self.assertEqual(report['scope']['eligible'], 0)
        self.assertEqual(report['scope']['withheld'], {'unapproved_name': 1})
        self.assertEqual(report['socket']['status'], 'skipped')
        self.assertNotIn('payroll', json.dumps(report))

    def test_exact_lockfiles_use_merge_base_not_base_tip(self):
        repo, base, merge, head = 'owner/project', 'a' * 40, 'b' * 40, 'c' * 40
        metadata = {'number': 9, 'state': 'open', 'draft': False,
                    'base': {'ref': 'main', 'sha': base, 'repo': {'full_name': repo}},
                    'head': {'sha': head, 'repo': {'full_name': repo}}}
        calls = []

        class API:
            def request(self, path):
                calls.append(path)
                if '/compare/' in path:
                    return {'merge_base_commit': {'sha': merge}}
                return metadata

            def blob(self, r, commit, path, *, limit):
                calls.append((r, commit, path))
                return commit.encode()

        info, before, after = pinned_lockfiles(API(), repo, 9, 'main')
        self.assertEqual((info['merge_base'], before, after), (merge, merge.encode(), head.encode()))
        self.assertEqual([x for x in calls if isinstance(x, tuple)],
                         [(repo, merge, 'pnpm-lock.yaml'), (repo, head, 'pnpm-lock.yaml')])
        metadata['head']['repo']['full_name'] = 'fork/project'
        with self.assertRaises(DependencyError):
            pinned_lockfiles(API(), repo, 9, 'main')

    def test_advisory_aliases_join_and_socket_signals_are_not_defects(self):
        before, after = lock({}), lock({'pkg@1.0.0': integrity(1)})
        known = {'package': 'pkg', 'version': '1.0.0', 'id': 'GHSA-aaaa-bbbb-cccc',
                 'aliases': ['CVE-2025-9999']}
        def socket(eligible):
            self.assertEqual(eligible, {('pkg', '1.0.0')})
            return {'status': 'ok', 'covered': 1, 'alerts': [
                {'package': 'pkg', 'version': '1.0.0', 'type': 'cve', 'ids': ['CVE-2025-9999']},
                {'package': 'pkg', 'version': '1.0.0', 'type': 'mediumCVE', 'ids': ['CVE-2025-8888']},
                {'package': 'pkg', 'version': '1.0.0', 'type': 'network', 'ids': ['CVE-2025-9999']},
                {'package': 'pkg', 'version': '1.0.0', 'type': 'gptMalware', 'ids': []},
                {'package': 'pkg', 'version': '1.0.0', 'type': 'malware', 'ids': ['MAL-2025-9999']},
            ]}
        def osv(raw, eligible):
            self.assertEqual((raw, eligible), (after, {('pkg', '1.0.0')}))
            return {'status': 'ok', 'advisories': [known]}
        report = audit(before, after, {'pkg'}, npm=lambda _: registry('pkg', '1.0.0', integrity(1)),
                       socket=socket, osv=osv)
        self.assertEqual([x['ids'] for x in report['comparison']['shared_advisories']], [['CVE-2025-9999']])
        self.assertEqual([x['ids'] for x in report['comparison']['socket_only_advisories']], [['CVE-2025-8888']])
        self.assertEqual([x['type'] for x in report['comparison']['socket_signals']], ['network'])
        self.assertEqual([x['type'] for x in report['comparison']['socket_suspected_malware']], ['gptMalware'])
        self.assertEqual([x['type'] for x in report['comparison']['socket_malware']], ['malware'])
