import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import activity
import backend as b


class ActivityTest(unittest.TestCase):
    def setUp(self):
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        patcher = patch.object(b, "STATE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_newest_events_are_returned_first_with_labels(self):
        activity.record("save_server", "completed", "192.0.2.10")
        activity.record("updates", "rejected", "2001:db8::1")
        events = activity.recent()
        self.assertEqual([event["action"] for event in events], ["updates", "save_server"])
        self.assertEqual(events[0]["label"], "Update operation")
        self.assertEqual(events[0]["result"], "rejected")
        self.assertEqual(events[0]["address"], "2001:db8::1")
        self.assertEqual(events[1]["label"], "Advanced configuration saved")

    def test_history_is_bounded_and_corrupt_lines_are_ignored(self):
        with patch.object(activity, "LIMIT", 3), patch.object(activity, "MAX_BYTES", 1):
            for index in range(8):
                activity.record(f"action-{index}", "completed", "192.0.2.1")
        with activity.path().open("a", encoding="utf-8") as stream:
            stream.write("not-json\n")
        events = activity.recent(10)
        self.assertEqual([event["action"] for event in events],
                         ["action-7", "action-6", "action-5"])
        self.assertTrue(all(event["label"].startswith("Action-") for event in events))

    def test_recording_never_raises_when_state_is_unwritable(self):
        blocker = self.state / "blocked"
        blocker.write_text("", encoding="utf-8")
        with patch.object(b, "STATE", blocker / "child"):
            activity.record("save_server")
        self.assertTrue(blocker.is_file())