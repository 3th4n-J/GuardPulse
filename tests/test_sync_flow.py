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
