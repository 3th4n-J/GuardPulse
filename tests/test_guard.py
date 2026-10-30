import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse import security  # noqa: E402
from guardpulse.domains import InvalidDomain, normalize_domain  # noqa: E402
from guardpulse.guard import Guard, GuardError, Locked, Schedule  # noqa: E402

PIN = "4826"


class Clock:
    def __init__(self, now: float = 1_800_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class GuardTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.clock = Clock()
        self.guard = self.make()

    def tearDown(self):
        self.guard.conn.close()
        self._tmp.cleanup()

    def make(self) -> Guard:
        return Guard(self.folder, clock=self.clock)

    def setup_partner(self) -> str:
        return self.guard.setup_partner("Sam", "sam@example.com", PIN)


class DomainTests(unittest.TestCase):
    def test_normalises_urls(self):
        self.assertEqual(normalize_domain("https://www.Example.com/path?q=1"), "example.com")
        self.assertEqual(normalize_domain("*.reddit.com"), "reddit.com")
        self.assertEqual(normalize_domain("m.youtube.com:443"), "m.youtube.com")
        self.assertEqual(normalize_domain("bücher.de"), "xn--bcher-kva.de")

    def test_rejects_junk(self):
        for bad in ("", "localhost", "not a site", "1.2.3.4", "-bad-.com"):
            with self.assertRaises(InvalidDomain, msg=bad):
                normalize_domain(bad)


class SecurityTests(unittest.TestCase):
    def test_pin_hash_roundtrip(self):
        stored = security.hash_pin("4826")
        self.assertTrue(security.verify_pin("4826", stored))
        self.assertFalse(security.verify_pin("4827", stored))
        self.assertNotIn("4826", stored)

    def test_weak_pins(self):
        for weak in ("12", "1111", "1234", "9876", "abcd"):
            with self.assertRaises(security.WeakPin, msg=weak):
                security.validate_pin(weak)
        self.assertEqual(security.validate_pin(" 4826 "), "4826")

    def test_pbkdf2_roundtrip(self):
        stored = security.pbkdf2_hash("4826")
        self.assertTrue(stored.startswith("pbkdf2$"))
        self.assertNotIn("4826", stored)
        self.assertTrue(security.verify_pbkdf2("4826", stored))
        self.assertFalse(security.verify_pbkdf2("4827", stored))
        self.assertFalse(security.verify_pbkdf2("4826", "bogus"))

    def test_totp_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA-1, T = 59 -> 94287082 (last 6 digits 287082)
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(security.totp_now(secret, at=59), "287082")

    def test_totp_rejects_replay(self):
        secret = security.new_totp_secret()
        code = security.totp_now(secret, at=1000)
        counter = security.verify_totp(secret, code, 0, at=1000)
        self.assertIsNotNone(counter)
        self.assertIsNone(security.verify_totp(secret, code, counter, at=1000))

    def test_lockout_backoff(self):
        self.assertEqual(security.lockout_seconds(2), 0)
        self.assertEqual(security.lockout_seconds(3), 30)
        self.assertEqual(security.lockout_seconds(4), 60)
        self.assertEqual(security.lockout_seconds(20), 3600)


class SetupModeTests(GuardTestCase):
    def test_everything_free_before_partner(self):
        self.assertFalse(self.guard.is_setup)
        self.assertTrue(self.guard.unlocked)
        rule = self.guard.add_allow("example.org")
        self.guard.remove_rule(rule.id)

    def test_partner_only_once(self):
        self.setup_partner()
        with self.assertRaises(GuardError):
            self.setup_partner()

    def test_pin_never_stored_plain(self):
        self.setup_partner()
        raw = (self.folder / "guardpulse.db").read_bytes()
        self.assertNotIn(PIN.encode(), raw)


class RatchetTests(GuardTestCase):
    def setUp(self):
        super().setUp()
        self.secret = self.setup_partner()

    def test_blocking_is_free(self):
        self.guard.add_block("https://bad.example.com/x")
        self.guard.add_app("com.zhiliaoapp.musically", "TikTok")
        self.guard.add_schedule("Bedtime", 0b1111111, 22 * 60, 6 * 60, ["org.telegram.messenger"])
        self.assertEqual(self.guard.stats()["blocked_sites"], 1)

    def test_loosening_needs_pin(self):
        rule = self.guard.add_block("bad.com")
        app = self.guard.add_app("com.reddit.frontpage")
        sched = self.guard.add_schedule("Work", 0b11111, 540, 1020, ["com.reddit.frontpage"])
        for attempt in (
            lambda: self.guard.add_allow("good.com"),
            lambda: self.guard.remove_rule(rule.id),
            lambda: self.guard.remove_app(app.id),
            lambda: self.guard.set_schedule_enabled(sched.id, False),
            lambda: self.guard.remove_schedule(sched.id),
            lambda: self.guard.set_setting("family_dns", False),
            lambda: self.guard.set_setting("unlock_minutes", 10),
            lambda: self.guard.set_setting("alert_webhook_url", "https://n8n.example/hook"),
            lambda: self.guard.change_pin("7391"),
        ):
            with self.assertRaises(Locked):
                attempt()

    def test_tightening_settings_is_free(self):
        self.guard.set_setting("uninstall_protection", True)
        self.guard.set_setting("unlock_minutes", 2)
        self.assertTrue(self.guard.setting("uninstall_protection"))

    def test_pin_unlocks_for_a_while(self):
        self.assertEqual(self.guard.unlock(PIN), "pin")
        self.guard.add_allow("good.com")
        self.clock.now += 5 * 60 + 1
        with self.assertRaises(Locked):
            self.guard.add_allow("other.com")

    def test_totp_unlock_once(self):
        code = security.totp_now(self.secret, at=self.clock.now)
        self.assertEqual(self.guard.unlock(code), "totp")
        self.guard.lock()
        with self.assertRaises(GuardError):
            self.guard.unlock(code)

    def test_restart_relocks(self):
        self.guard.unlock(PIN)
        self.guard.conn.close()
        self.guard = self.make()
        self.assertFalse(self.guard.unlocked)

    def test_wrong_pin_lockout_survives_restart(self):
        for _ in range(3):
            with self.assertRaises(GuardError):
                self.guard.unlock("0000")
        self.guard.conn.close()
        self.guard = self.make()
        with self.assertRaisesRegex(GuardError, "Too many"):
            self.guard.unlock(PIN)
        self.clock.now += 31
        self.assertEqual(self.guard.unlock(PIN), "pin")

    def test_loosening_queues_partner_alert(self):
        self.guard.unlock(PIN)
        self.guard.add_allow("good.com")
        events = [r["event"] for r in self.guard.pending_alerts()]
        self.assertIn("unlocked", events)
        self.assertIn("whitelisted", events)


class DecisionTests(GuardTestCase):
    def test_most_specific_rule_wins(self):
        g = self.guard
        g.add_block("example.com")
        g.add_allow("docs.example.com")
        g.add_block("private.docs.example.com")
        self.assertEqual(g.decide("www.example.com"), "block")
        self.assertEqual(g.decide("docs.example.com"), "allow")
        self.assertEqual(g.decide("a.private.docs.example.com"), "block")
        self.assertEqual(g.decide("unrelated.org"), "default")

    def test_wildcard_input_covers_all_subdomains(self):
        rule = self.guard.add_block("*.example.com")
        self.assertEqual(rule.value, "example.com")
        for host in ("example.com", "www.example.com", "a.b.c.example.com", "https://m.example.com/x"):
            self.assertEqual(self.guard.decide(host), "block", host)
        self.assertEqual(self.guard.decide("notexample.com"), "default")

    def test_equal_rules_allow_wins(self):
        self.guard.add_block("example.com")
        self.guard.add_allow("example.com")
        self.assertEqual(self.guard.decide("example.com"), "allow")


class ScheduleTests(unittest.TestCase):
    def test_daytime_window(self):
        s = Schedule(1, "Work", 0b0011111, 9 * 60, 17 * 60, ("a.b",), True)
        self.assertTrue(s.active_at(datetime(2026, 10, 26, 10, 0)))  # Monday
        self.assertFalse(s.active_at(datetime(2026, 10, 26, 17, 0)))
        self.assertFalse(s.active_at(datetime(2026, 11, 1, 10, 0)))  # Sunday

    def test_overnight_window_uses_start_day(self):
        friday_only = Schedule(1, "Night", 1 << 4, 22 * 60, 6 * 60, ("a.b",), True)
        self.assertTrue(friday_only.active_at(datetime(2026, 10, 30, 23, 0)))  # Fri 23:00
        self.assertTrue(friday_only.active_at(datetime(2026, 10, 31, 5, 59)))  # Sat 05:59
        self.assertFalse(friday_only.active_at(datetime(2026, 10, 31, 23, 0)))  # Sat 23:00
        self.assertFalse(friday_only.active_at(datetime(2026, 10, 30, 5, 0)))  # Fri 05:00


class TamperTests(GuardTestCase):
    def test_outside_edit_is_detected(self):
        self.setup_partner()
        self.guard.add_block("bad.com")
        self.guard.conn.close()
        raw = sqlite3.connect(self.folder / "guardpulse.db")
        raw.execute("DELETE FROM rules")
        raw.commit()
        raw.close()
        self.guard = self.make()
        self.assertTrue(self.guard.tampered)
        self.assertIn("tamper", [r["event"] for r in self.guard.pending_alerts()])
        with self.assertRaises(Locked):
            self.guard.acknowledge_tamper()
        self.guard.unlock(PIN)
        self.guard.acknowledge_tamper()
        self.guard.conn.close()
        self.guard = self.make()
        self.assertFalse(self.guard.tampered)

    def test_clean_reopen_is_not_tamper(self):
        self.setup_partner()
        self.guard.add_block("bad.com")
        self.guard.conn.close()
        self.guard = self.make()
        self.assertFalse(self.guard.tampered)

    def test_policy_file_is_signed(self):
        self.guard.add_block("bad.com")
        payload = (self.folder / "policy.json").read_bytes()
        sig = (self.folder / "policy.sig").read_text()
        self.assertTrue(security.seal_ok(self.guard.keys.get_key(), payload, sig))
        self.assertEqual(json.loads(payload)["block"], ["bad.com"])


class NativeGlueTests(GuardTestCase):
    def test_filter_off_needs_partner_and_alerts(self):
        self.setup_partner()
        with self.assertRaises(Locked):
            self.guard.authorise_filter_off()
        self.guard.unlock(PIN)
        self.guard.authorise_filter_off()
        self.assertIn("protection_disabled", [r["event"] for r in self.guard.pending_alerts()])

    def test_native_pin_file_written_and_sealed(self):
        self.setup_partner()
        payload = (self.folder / "pin.verify").read_bytes()
        sig = (self.folder / "pin.verify.sig").read_text()
        self.assertTrue(security.seal_ok(self.guard.keys.get_key(), payload, sig))
        self.assertTrue(security.verify_pbkdf2(PIN, payload.decode()))
        self.assertNotIn(PIN.encode(), payload)  # a hash, not the PIN

    def test_native_pin_file_follows_pin_change(self):
        self.setup_partner()
        self.guard.unlock(PIN)
        self.guard.change_pin("7391")
        payload = (self.folder / "pin.verify").read_bytes()
        self.assertTrue(security.verify_pbkdf2("7391", payload.decode()))
        self.assertFalse(security.verify_pbkdf2(PIN, payload.decode()))

    def test_uninstall_off_needs_partner(self):
        self.setup_partner()
        with self.assertRaises(Locked):
            self.guard.authorise_uninstall_off()
        self.guard.unlock(PIN)
        self.guard.authorise_uninstall_off()
        self.assertEqual(self.guard.history(1)[0]["action"], "uninstall.disabled")

    def test_settings_guard_toggle_ratchet(self):
        self.setup_partner()
        self.guard.set_setting("settings_guard", True)  # turning on is free
        self.assertTrue(self.guard.setting("settings_guard"))
        with self.assertRaises(Locked):  # turning off needs the partner
            self.guard.set_setting("settings_guard", False)

    def test_overlay_off_needs_partner(self):
        self.setup_partner()
        with self.assertRaises(Locked):
            self.guard.authorise_overlay_off()
        self.guard.unlock(PIN)
        self.guard.authorise_overlay_off()
        self.assertEqual(self.guard.history(1)[0]["action"], "overlay.disabled")

    def test_overlay_disabled_outside_app_is_tamper(self):
        self.guard.record_native("accessibility_disabled", "switched off in settings")
        self.assertTrue(self.guard.tampered)

    def test_overlay_off_warning(self):
        from guardpulse.native import NativeBridge

        bridge = NativeBridge(folder=self.folder)
        bridge.state = {"overlay_wanted": True, "overlay_enabled": False}
        self.assertIsNotNone(bridge.overlay_off_warning())
        bridge.state = {"overlay_wanted": True, "overlay_enabled": True}
        self.assertIsNone(bridge.overlay_off_warning())
        self.assertTrue(bridge.overlay_running)

    def test_policy_carries_apps_and_schedules_for_overlay(self):
        self.guard.add_app("com.reddit.frontpage", "Reddit")
        self.guard.add_schedule("Night", 0b1111111, 22 * 60, 6 * 60, ["org.telegram.messenger"])
        policy = json.loads((self.folder / "policy.json").read_text())
        self.assertEqual(policy["apps"], ["com.reddit.frontpage"])
        self.assertEqual(policy["schedules"][0]["packages"], ["org.telegram.messenger"])
        self.assertTrue(policy["settings"]["feed_youtube_shorts"])

    def test_native_tamper_events_raise_warning(self):
        self.guard.record_native("vpn_not_prepared", "permission missing")
        self.assertFalse(self.guard.tampered)
        self.guard.record_native("vpn_revoked", "switched off in settings")
        self.assertTrue(self.guard.tampered)

    def test_drain_events_reads_once(self):
        from guardpulse.native import NativeBridge

        bridge = NativeBridge(folder=self.folder)
        path = self.folder / "native_events.jsonl"
        path.write_text(
            '{"at": 1, "event": "vpn_revoked", "detail": "x"}\nnot json\n', encoding="utf-8"
        )
        self.assertEqual([e["event"] for e in bridge.drain_events()], ["vpn_revoked"])
        self.assertEqual(bridge.drain_events(), [])
        self.assertFalse(bridge.available)

    def test_lockdown_warning(self):
        from guardpulse.native import NativeBridge

        bridge = NativeBridge(folder=self.folder)
        bridge.state = {"vpn_running": True, "lockdown": True}
        self.assertIn("ALL internet", bridge.lockdown_warning())
        bridge.state = {"vpn_running": True, "lockdown": False}
        self.assertIsNone(bridge.lockdown_warning())
        bridge.state = {"vpn_running": False, "lockdown": True}  # filter off: lockdown irrelevant
        self.assertIsNone(bridge.lockdown_warning())

    def test_private_dns_warning(self):
        from guardpulse.native import NativeBridge

        bridge = NativeBridge(folder=self.folder)
        bridge.state = {"private_dns_mode": "hostname", "private_dns_host": "dns.google"}
        self.assertIn("dns.google", bridge.private_dns_warning())
        bridge.state = {"private_dns_mode": "hostname", "private_dns_host": "family.cloudflare-dns.com"}
        self.assertIsNone(bridge.private_dns_warning())
        bridge.state = {"private_dns_mode": "opportunistic"}
        self.assertIsNone(bridge.private_dns_warning())


if __name__ == "__main__":
    unittest.main()
