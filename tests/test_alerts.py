import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse import alerts  # noqa: E402
from guardpulse.guard import NTFY_TOPIC_RE, Guard  # noqa: E402

PIN = "4826"


class FakeNtfy:
    def __init__(self, fail_after: int | None = None):
        self.sent: list[tuple[str, str, alerts.Alert]] = []
        self.fail_after = fail_after

    def __call__(self, server, topic, alert):
        if self.fail_after is not None and len(self.sent) >= self.fail_after:
            raise OSError("offline")
        self.sent.append((server, topic, alert))


class AlertTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.guard = Guard(Path(self._tmp.name))

    def tearDown(self):
        self.guard.conn.close()
        self._tmp.cleanup()

    def setup_partner(self):
        self.guard.setup_partner("Sam", "", PIN)

    def test_no_topic_before_partner(self):
        self.assertEqual(self.guard.setting("ntfy_topic"), "")
        self.assertEqual(self.guard.ensure_alert_topic(), "")

    def test_partner_setup_creates_unguessable_topic(self):
        self.setup_partner()
        topic = self.guard.setting("ntfy_topic")
        self.assertTrue(topic.startswith("guardpulse-"))
        self.assertTrue(NTFY_TOPIC_RE.fullmatch(topic))
        self.assertGreaterEqual(len(topic), 30)  # 96 random bits
        other = Guard(Path(tempfile.mkdtemp()))
        other.setup_partner("Sam", "", PIN)
        self.assertNotEqual(topic, other.setting("ntfy_topic"))
        other.conn.close()

    def test_topic_is_in_the_signed_policy_for_kotlin(self):
        self.setup_partner()
        self.guard.add_block("bad.com")  # rewrites policy.json
        self.assertEqual(self.guard.policy()["settings"]["ntfy_topic"], self.guard.setting("ntfy_topic"))

    def test_existing_partner_gets_topic_on_upgrade(self):
        self.setup_partner()
        # simulate a pre-0.6 database: partner exists, topic empty
        self.guard.conn.execute("UPDATE settings SET value = '\"\"' WHERE key = 'ntfy_topic'")
        topic = self.guard.ensure_alert_topic()
        self.assertTrue(topic.startswith("guardpulse-"))

    def test_deliver_sends_and_marks(self):
        self.setup_partner()
        self.guard.unlock(PIN)
        self.guard.add_allow("example.org")
        fake = FakeNtfy()
        sent, failed = alerts.deliver_pending(self.guard, send=fake)
        self.assertEqual(failed, 0)
        self.assertEqual(sent, 2)  # unlocked + whitelisted
        self.assertEqual(self.guard.pending_alerts(), [])
        server, topic, alert = fake.sent[1]
        self.assertEqual(server, "https://ntfy.sh")
        self.assertEqual(topic, self.guard.setting("ntfy_topic"))
        self.assertEqual(alert.title, "Site whitelisted")
        self.assertIn("example.org", alert.message)

    def test_offline_keeps_queue_and_retries(self):
        self.setup_partner()
        self.guard.unlock(PIN)
        self.guard.add_allow("example.org")
        sent, failed = alerts.deliver_pending(self.guard, send=FakeNtfy(fail_after=0))
        self.assertEqual((sent, failed), (0, 1))
        self.assertEqual(len(self.guard.pending_alerts()), 2)
        sent, failed = alerts.deliver_pending(self.guard, send=FakeNtfy())
        self.assertEqual((sent, failed), (2, 0))

    def test_async_delivery(self):
        self.setup_partner()
        self.guard.queue_test_alert()
        fake = FakeNtfy()
        sent, failed = asyncio.run(alerts.deliver_pending_async(self.guard, send=fake))
        self.assertEqual((sent, failed), (1, 0))
        self.assertEqual(fake.sent[0][2].title, "GuardPulse test alert")

    def test_nothing_sent_without_topic(self):
        self.guard.queue_test_alert()
        self.assertEqual(alerts.deliver_pending(self.guard, send=FakeNtfy()), (0, 0))

    def test_native_tamper_is_not_double_alerted(self):
        """Kotlin already alerted the partner; Python must only flag + log it."""
        self.setup_partner()
        self.guard.record_native("vpn_revoked", "switched off in settings")
        self.assertTrue(self.guard.tampered)
        self.assertNotIn("tamper", [r["event"] for r in self.guard.pending_alerts()])

    def test_python_detected_tamper_is_alerted(self):
        self.setup_partner()
        self.guard.report_tamper("database edited outside GuardPulse")
        self.assertIn("tamper", [r["event"] for r in self.guard.pending_alerts()])

    def test_describe_covers_every_queued_event(self):
        events = [
            ("unlocked", {"method": "pin"}),
            ("unlocked", {"method": "totp"}),
            ("unlock_failed", {"attempts": 3}),
            ("whitelisted", {"value": "a.com"}),
            ("rule_removed", {"kind": "block", "value": "b.com"}),
            ("app_unblocked", {"package": "com.x"}),
            ("schedule_removed", {"name": "Night"}),
            ("pin_changed", {}),
            ("protection_disabled", {"setting": "family_dns"}),
            ("tamper", {"what": "x"}),
            ("test", {}),
        ]
        for event, payload in events:
            a = alerts.describe(event, payload)
            self.assertTrue(a.title and a.message, event)
            a.title.encode("latin-1")  # ntfy headers must be latin-1
            self.assertIn(a.priority, range(1, 6))
        self.assertEqual(alerts.describe("protection_disabled", {"setting": "family_dns"}).message,
                         "Cloudflare Family DNS was switched off.")


if __name__ == "__main__":
    unittest.main()
