import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.alert_triage import AlertTriageEngine
from scripts.generate_sample_data import SecurityEventGenerator
from scripts.soc_analysis import SOCAnalysisWorkflow


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.engine = AlertTriageEngine()

    def events(self, count=5, spacing=1, event_id=4625, logon_type=3):
        return [dict(event_id=event_id, timestamp=f'2026-01-01T00:{i * spacing:02}:00Z',
                     username='alice', hostname=f'host{i}', source_ip='203.0.113.45',
                     logon_type=logon_type) for i in range(count)]

    def test_brute_force_window_and_integer_ids(self):
        self.assertEqual(len(self.engine.correlate_alerts(self.events())['brute_force_attacks']), 1)
        self.assertFalse(self.engine.correlate_alerts(self.events(spacing=12))['brute_force_attacks'])

    def test_lateral_movement_requires_remote_logons(self):
        for kind, expected in [(2, 0), (3, 1), (10, 1)]:
            findings = self.engine.correlate_alerts(self.events(event_id=4624, logon_type=kind))
            self.assertEqual(len(findings['lateral_movement']), expected)
        self.assertFalse(self.engine.correlate_alerts(self.events(spacing=12, event_id=4624))['lateral_movement'])

    def test_privileges_require_prior_same_host_logon(self):
        logon = self.events(1, event_id=4624)[0]
        privilege = dict(logon, event_id=4672, timestamp='2026-01-01T00:02:00+00:00')
        self.assertEqual(len(self.engine.detect_privilege_escalation([privilege, logon])), 1)
        for changed in [dict(logon, hostname='other'), dict(logon, timestamp='2026-01-01T00:03:00Z'), dict(logon, timestamp='bad')]:
            self.assertFalse(self.engine.detect_privilege_escalation([privilege, changed]))

    def test_unique_incident_ids(self):
        ids = [self.engine.generate_incident_report({}, 12, [], 'HIGH')['incident_metadata']['incident_id'] for _ in range(100)]
        self.assertEqual(len(set(ids)), 100)

    def test_address_validation(self):
        for address in ['10.0.0.1', '172.31.0.1', '::1', 'fd00::1', '::ffff:192.168.1.2']:
            self.assertTrue(self.engine.is_internal_ip(address), address)
        for address in ['203.0.113.45', '172.32.0.1', '10.invalid', '']:
            self.assertFalse(self.engine.is_internal_ip(address), address)

    def test_generator_bare_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'events.json'
            SecurityEventGenerator().save_events([], target)
            self.assertEqual(json.loads(target.read_text()), [])

    def test_workflow_rejects_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'events.json'
            workflow = SOCAnalysisWorkflow()
            workflow.data_file = str(target)
            for payload in [{}, [None], [{'username': None}]]:
                target.write_text(json.dumps(payload))
                self.assertIsNone(workflow.load_security_events())

    def test_generated_malware_receives_high_priority(self):
        from datetime import datetime
        events = SecurityEventGenerator().generate_malware_execution_scenario(datetime(2026, 1, 1))
        for event in events:
            score, _ = self.engine.analyze_alert(event)
            self.assertIn(self.engine.get_priority(score), ('HIGH', 'CRITICAL'))

    def test_save_failure_is_reported(self):
        workflow = SOCAnalysisWorkflow()
        with patch('builtins.open', side_effect=OSError('disk full')):
            self.assertFalse(workflow.save_results())


if __name__ == '__main__':
    unittest.main()
