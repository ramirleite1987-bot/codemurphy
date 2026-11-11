import unittest

from codemurphy.socket_reports import normalize


class SocketReportTests(unittest.TestCase):
    def test_coverage_and_alerts_are_bound_to_exact_requested_releases(self):
        eligible = {('vite', '8.3.6'), ('rolldown', '1.2.16')}
        rows = [
            {'package': 'vite', 'version': '8.3.6', 'alerts': [
                {'type': 'cve', 'severity': 'high', 'ids': ['CVE-2026-45678', 'GHSA-abcd-2345-6789']},
                {'type': 'network', 'severity': 'medium', 'ids': ['not-an-advisory']},
            ]},
            {'package': 'rolldown', 'version': '1.2.16', 'alerts': [
                {'type': 'pendingScan', 'severity': 'low', 'ids': []},
            ]},
        ]
        result = normalize(rows, eligible)
        self.assertEqual((result['status'], result['covered']), ('partial', 1))
        self.assertEqual([(x['type'], x['ids']) for x in result['alerts']], [
            ('cve', ['CVE-2026-45678', 'GHSA-abcd-2345-6789']), ('network', []),
        ])

    def test_unsolicited_or_duplicate_results_fail_closed(self):
        row = {'package': 'vite', 'version': '8.3.6', 'alerts': []}
        for rows in ([row, row], [{**row, 'version': '8.3.5'}]):
            self.assertEqual(normalize(rows, {('vite', '8.3.6')})['status'], 'error')

    def test_malformed_alert_is_not_an_empty_success(self):
        row = {'package': 'vite', 'version': '8.3.6', 'alerts': [{'type': {'bad': 'type'}}]}
        result = normalize([row], {('vite', '8.3.6')})
        self.assertNotEqual(result['status'], 'ok')
