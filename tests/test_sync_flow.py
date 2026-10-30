import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse.guard import Guard, Locked  # noqa: E402
from guardpulse.sync.firebase import Config, Conflict, Session  # noqa: E402
from guardpulse.sync.manager import SyncError, SyncManager  # noqa: E402

PIN = "4826"
CONFIG = Config(api_key="k", project_id="p", web_client_id="w")


class FakeCloud:
    """Firestore stand-in: one document per uid, updateTime preconditions, readable blobs."""

    def __init__(self):
        self.docs: dict[str, tuple[str, int, str]] = {}
        self.writes = 0
        self.fail_next_put = False

    def sign_in_with_google(self, token: str) -> Session:
        uid = "uid-" + token  # the fake "Google token" is just the account name
        return Session(uid=uid, email=f"{token}@gmail.com", id_token="t", refresh_token="r", expires_at=9e12)

    def fresh(self, session):
        return session

    def get_state(self, session):
        if session.uid not in self.docs:
            return None, 0, None
        return self.docs[session.uid]

    def put_state(self, session, blob, rev, update_time):
        current = self.docs.get(session.uid)
        if self.fail_next_put:
            self.fail_next_put = False
            raise Conflict("simulated race")
        if (current[2] if current else None) != update_time:
            raise Conflict("stale")
        self.writes += 1
        stamp = f"t{self.writes}"
        self.docs[session.uid] = (blob, rev, stamp)
        return stamp


def phone(cloud) -> tuple[Guard, SyncManager]:
    guard = Guard(Path(tempfile.mkdtemp()))
    return guard, SyncManager(guard, config=CONFIG, firebase=cloud)


class SyncFlowTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeCloud()
        self.a, self.sa = phone(self.cloud)
        self.b, self.sb = phone(self.cloud)
        self.a.setup_partner("Sam", "", PIN)
        self.a.add_block("reddit.com")
        self.a.add_app("com.zhiliaoapp.musically", "TikTok")

    def tearDown(self):
        self.a.conn.close()
        self.b.conn.close()

    def pair_b(self):
        self.assertEqual(self.sa.sign_in("ethan"), "synced")  # first phone uploads
        self.assertEqual(self.sb.sign_in("ethan"), "needs_pair")
        self.a.unlock(PIN)
        code = self.sa.pairing_code()
        self.a.lock()
        self.sb.pair(code)

    def test_cloud_never_sees_plaintext(self):
        self.sa.sign_in("ethan")
        blob = self.cloud.docs["uid-ethan"][0]
        for secret in ("reddit", "TikTok", "Sam", "pin_hash"):
            self.assertNotIn(secret, blob)

    def test_second_phone_pairs_and_receives_everything(self):
        self.pair_b()
        self.assertEqual([r.value for r in self.b.rules("block")], ["reddit.com"])
        self.assertEqual([x.package for x in self.b.blocked_apps()], ["com.zhiliaoapp.musically"])
        self.assertTrue(self.b.is_setup)
        self.assertEqual(self.b.unlock(PIN), "pin")  # same partner PIN works on phone B
        self.assertFalse(self.b.tampered)

    def test_pairing_code_needs_partner(self):
        self.sa.sign_in("ethan")
        with self.assertRaises(Locked):
            self.sa.pairing_code()

    def test_changes_flow_both_ways(self):
        self.pair_b()
        self.b.add_block("x.com")
        self.sb.sync_now()
        self.sa.sync_now()
        self.assertIn("x.com", [r.value for r in self.a.rules("block")])
        self.a.add_schedule("Night", 0b1111111, 22 * 60, 6 * 60, ["org.telegram.messenger"])
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertEqual(self.b.schedules()[0].name, "Night")

    def test_removal_with_pin_syncs_but_concurrent_addition_survives(self):
        self.pair_b()
        rule = self.a.rules("block")[0]
        self.a.unlock(PIN)
        self.a.remove_rule(rule.id)  # approved on phone A
        self.b.add_block("new.com")  # meanwhile on phone B, not yet synced
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertEqual([r.value for r in self.b.rules("block")], ["new.com"])
        self.sa.sync_now()
        self.assertEqual([r.value for r in self.a.rules("block")], ["new.com"])

    def test_wrong_account_code_is_refused(self):
        self.sa.sign_in("ethan")
        self.a.unlock(PIN)
        code = self.sa.pairing_code()
        self.sb.sign_in("someoneelse")
        with self.assertRaisesRegex(SyncError, "different Google account"):
            self.sb.pair(code)

    def test_race_is_retried(self):
        self.pair_b()
        self.b.add_block("race.com")
        self.cloud.fail_next_put = True
        self.sb.sync_now()  # first put conflicts, second succeeds
        self.sa.sync_now()
        self.assertIn("race.com", [r.value for r in self.a.rules("block")])

    def test_activity_from_other_phone_shows_up(self):
        self.pair_b()
        self.b.add_block("seen.com")
        self.sb.sync_now()
        self.sa.sync_now()
        devices = {row["device"] for row in self.a.history(100)}
        self.assertIn(self.b.device_id, devices)

    def test_nothing_changed_no_write(self):
        self.pair_b()
        self.sa.sync_now()
        self.sb.sync_now()
        writes = self.cloud.writes
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertEqual(self.cloud.writes, writes)

    def test_sign_out_needs_partner(self):
        self.sa.sign_in("ethan")
        with self.assertRaises(Locked):
            self.sa.sign_out()
        self.a.unlock(PIN)
        self.sa.sign_out()
        self.assertFalse(self.sa.status().signed_in)
        self.assertFalse(self.sa.status().paired)

    def test_tampered_base_falls_back_safely(self):
        self.pair_b()
        base = self.a.folder / "sync_base.json"
        base.write_text(base.read_text().replace("reddit.com", "evil.com"))
        self.sa.sync_now()  # sealed base rejected -> union merge, nothing lost
        self.assertIn("reddit.com", [r.value for r in self.a.rules("block")])

    def blocks(self, guard):
        return [r.value for r in guard.rules("block")]

    def test_old_copy_put_back_is_refused_and_reported(self):
        self.pair_b()
        old_copy = self.cloud.docs["uid-ethan"]
        self.a.add_block("later.com")  # partner adds a rule after the copy was saved
        self.a.unlock(PIN)
        self.a.set_setting("dork_guard", True)
        self.a.lock()
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertIn("later.com", self.blocks(self.b))
        blob, rev, stamp = self.cloud.docs["uid-ethan"]
        self.cloud.docs["uid-ethan"] = (old_copy[0], rev + 99, stamp)  # replay, plaintext rev faked higher
        self.sb.sync_now()
        self.assertIn("later.com", self.blocks(self.b))  # nothing removed
        self.assertTrue(self.b.tampered)
        self.assertIn("tamper", [r["event"] for r in self.b.pending_alerts()])
        self.sa.sync_now()  # B healed the cloud copy; A keeps everything and sees no rollback
        self.assertIn("later.com", self.blocks(self.a))
        self.assertFalse(self.a.tampered)

    def test_split_history_never_removes_rules(self):
        self.pair_b()
        replayable = self.cloud.docs["uid-ethan"]
        self.b.add_block("partner-added.com")  # B moves ahead; A hasn't seen it
        self.sb.sync_now()
        self.cloud.docs["uid-ethan"] = replayable  # older copy put back...
        self.a.add_block("a-side.com")
        self.sa.sync_now()  # ...A builds on top of it
        self.sb.sync_now()
        self.assertIn("partner-added.com", self.blocks(self.b))
        self.assertIn("a-side.com", self.blocks(self.b))
        self.sa.sync_now()
        self.assertIn("partner-added.com", self.blocks(self.a))
        self.assertIn("a-side.com", self.blocks(self.a))

    def test_replayed_whitelist_is_not_restored(self):
        self.a.unlock(PIN)
        self.a.add_allow("ok.example")
        self.a.lock()
        self.pair_b()
        with_allow = self.cloud.docs["uid-ethan"]
        self.b.unlock(PIN)
        self.b.remove_rule(self.b.rules("allow")[0].id)
        self.b.lock()
        self.sb.sync_now()
        self.cloud.docs["uid-ethan"] = with_allow
        self.sb.sync_now()
        self.assertEqual(self.b.rules("allow"), [])

    def test_loosening_from_sync_is_logged_and_alerted(self):
        self.pair_b()
        self.a.unlock(PIN)
        self.a.remove_rule(self.a.rules("block")[0].id)
        self.a.lock()
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertEqual(self.blocks(self.b), [])
        self.assertIn("sync.loosened", [r["action"] for r in self.b.history(50)])
        alerts = [r for r in self.b.pending_alerts() if r["event"] == "sync_loosened"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("reddit.com unblocked", alerts[0]["payload"])

    def test_copy_from_before_v1_is_upgraded(self):
        import json

        from guardpulse.sync import crypto, state

        self.sa.sign_in("ethan")
        key, uid = self.sa.key, "uid-ethan"
        legacy = crypto.open_(key, uid, self.cloud.docs[uid][0])
        legacy.pop("rev")
        legacy.pop("lineage")
        blob, rev, stamp = self.cloud.docs[uid]
        self.cloud.docs[uid] = (crypto.seal(key, uid, legacy), rev, stamp)
        base = self.a.folder / "sync_base.json"
        raw = json.loads(base.read_text())
        body = json.dumps(raw["state"], sort_keys=True).encode()
        from guardpulse import security

        base.write_text(json.dumps({"state": raw["state"], "seal": security.seal(self.a.keys.get_key(), body)}))
        self.sa.sync_now()
        self.assertFalse(self.a.tampered)
        upgraded = crypto.open_(key, uid, self.cloud.docs[uid][0])
        self.assertIn("lineage", upgraded)
        self.assertEqual(state.digest(upgraded), state.digest(legacy))

    def test_keywords_and_always_allow_sync(self):
        self.pair_b()
        self.a.add_keyword("casino")
        self.a.unlock(PIN)
        self.a.add_always_allow("com.bible.app", "Bible")
        self.a.lock()
        self.sa.sync_now()
        self.sb.sync_now()
        self.assertEqual(self.b.keywords(), ["casino"])
        self.assertEqual(self.b.always_allowed(), ["com.bible.app"])
        alert = next(r for r in self.b.pending_alerts() if r["event"] == "sync_loosened")
        self.assertIn("com.bible.app always allowed", alert["payload"])

    def test_replayed_always_allow_is_not_restored(self):
        self.a.unlock(PIN)
        self.a.add_always_allow("com.bible.app", "Bible")
        self.a.lock()
        self.pair_b()
        old_copy = self.cloud.docs["uid-ethan"]
        self.b.remove_rule(self.b.rules("app_allow")[0].id)  # stricter: free
        self.sb.sync_now()
        self.cloud.docs["uid-ethan"] = old_copy
        self.sb.sync_now()
        self.assertEqual(self.b.always_allowed(), [])

    def test_async_twins_match(self):
        import asyncio

        self.assertEqual(asyncio.run(self.sa.sign_in_async("ethan")), "synced")
        self.assertEqual(asyncio.run(self.sb.sign_in_async("ethan")), "needs_pair")
        self.a.unlock(PIN)
        asyncio.run(self.sb.pair_async(self.sa.pairing_code()))
        self.assertEqual([r.value for r in self.b.rules("block")], ["reddit.com"])
        self.b.add_block("async.com")
        asyncio.run(self.sb.sync_now_async())
        asyncio.run(self.sa.sync_now_async())
        self.assertIn("async.com", [r.value for r in self.a.rules("block")])

    def test_not_configured(self):
        guard = Guard(Path(tempfile.mkdtemp()))
        mgr = SyncManager(guard, config=Config(), firebase=self.cloud)
        self.assertFalse(mgr.status().configured)
        with self.assertRaisesRegex(SyncError, "isn't set up"):
            mgr.sign_in("ethan")
        guard.conn.close()


if __name__ == "__main__":
    unittest.main()
