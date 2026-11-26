import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import monitoring
import service_logs


class MonitoringTest(unittest.TestCase):
    def test_samples_rates_and_drops_data_outside_retention(self):
        metrics = {"ram": 30, "disk": 10, "uptime": 400, "traffic": (100, 200)}
        with TemporaryDirectory() as directory, patch.object(monitoring, "host_metrics", return_value=metrics), patch.object(
            monitoring, "cpu_counters", side_effect=[(100, 30), (200, 80), (100, 40), (200, 100)]
        ):
            root = Path(directory)
            monitoring.collect_sample(root, now=100)
            metrics.update(uptime=460, traffic=(220, 440))
            monitoring.collect_sample(root, now=160)
            metrics.update(uptime=15, traffic=(500, 600))
            monitoring.collect_sample(root, now=220)
            points = monitoring.history(root, "1h", now=220)
            self.assertEqual(points[1], (160, 50, 30, 10, 2, 4))
            self.assertEqual(points[2], (220, None, 30, 10, None, None))
            future = 221 + monitoring.RETENTION
            monitoring.collect_sample(root, now=future)
            self.assertEqual([row[0] for row in monitoring.history(root, "30d", now=future)], [future])

    def test_journal_source_and_filters(self):
        events = [{"__REALTIME_TIMESTAMP": 1_000_000, "MESSAGE": "[Warning] before"},
                  {"__REALTIME_TIMESTAMP": 2_000_000, "MESSAGE": "[Warning] Outbound"},
                  {"__REALTIME_TIMESTAMP": 3_000_000, "MESSAGE": "[Debug] outbound"}]
        with patch.object(service_logs.b, "command", return_value="bad\n" + "\n".join(map(json.dumps, events))) as command:
            rows = service_logs.read_logs("xray", query="OUTBOUND", priority=4, after=2)
        self.assertEqual([(row["level"], row["message"]) for row in rows], [("Warning", "[Warning] Outbound")])
        command.assert_called_once_with(["/usr/bin/sudo", "-n", "/usr/bin/journalctl", "--no-pager", "--output=json",
                                         "--lines=500", "--unit=ttui-router.service", "--identifier=ttui-xray"], timeout=10)
