import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse import security  # noqa: E402
from guardpulse.guard import Guard, Locked  # noqa: E402
from guardpulse.sync import crypto, state  # noqa: E402

PIN = "4826"


def phone() -> Guard:
    return Guard(Path(tempfile.mkdtemp()))


class CryptoTests(unittest.TestCase):
    def test_round_trip(self):
        key = crypto.new_key()
        snap = {"rules": [["block", "reddit.com"]], "n": 1}
        blob = crypto.seal(key, "uid-1", snap)
        self.assertNotIn("reddit", blob)  # nothing readable in the cloud
        self.assertEqual(crypto.open_(key, "uid-1", blob), snap)

    def test_wrong_key_wrong_account_or_tampered_fail(self):
        key = crypto.new_key()
        blob = crypto.seal(key, "uid-1", {"a": 1})
        with self.assertRaises(crypto.SyncCryptoError):
            crypto.open_(crypto.new_key(), "uid-1", blob)
        with self.assertRaises(crypto.SyncCryptoError):
            crypto.open_(key, "uid-2", blob)  # replayed into another account
        tampered = blob[:-6] + ("A" if blob[-6] != "A" else "B") + blob[-5:]
        with self.assertRaises(crypto.SyncCryptoError):
            crypto.open_(key, "uid-1", tampered)

    def test_pair_code(self):
        key = crypto.new_key()
        code = crypto.pair_code("abcUID123", key)
        self.assertEqual(crypto.parse_pair_code(code), ("abcUID123", key))
        for bad in ("", "hello", "guardpulse-pair:1:uid:short"):
            with self.assertRaises(crypto.SyncCryptoError):
                crypto.parse_pair_code(bad)

    def test_key_file(self):
        folder = Path(tempfile.mkdtemp())
        self.assertIsNone(crypto.load_key(folder))
        key = crypto.new_key()
        crypto.save_key(folder, key)
        self.assertEqual(crypto.load_key(folder), key)
        crypto.forget_key(folder)
        self.assertIsNone(crypto.load_key(folder))


class MergeTests(unittest.TestCase):
    BASE = {
        "rules": [["block", "a.com"], ["block", "b.com"]],
        "apps": [["com.x", "X"]],
        "schedules": [],
        "settings": {"family_dns": True, "unlock_minutes": 5, "dork_guard": True},
        "partner": None,
    }

    def variant(self, **changes):
        s = copy.deepcopy(self.BASE)
        s.update(changes)
        return s

    def test_additions_from_both_phones_are_kept(self):
        local = self.variant(rules=self.BASE["rules"] + [["block", "c.com"]])
        remote = self.variant(rules=self.BASE["rules"] + [["block", "d.com"]])
        merged = state.merge(self.BASE, local, remote)
        self.assertEqual({v for _, v in merged["rules"]}, {"a.com", "b.com", "c.com", "d.com"})

    def test_removal_on_other_phone_syncs(self):
        remote = self.variant(rules=[["block", "a.com"]])  # b.com removed (with PIN) remotely
        merged = state.merge(self.BASE, self.BASE, remote)
        self.assertEqual(merged["rules"], [["block", "a.com"]])

    def test_untouched_local_stays(self):
        merged = state.merge(self.BASE, self.BASE, self.BASE)
        self.assertEqual(merged["rules"], self.BASE["rules"])

    def test_settings_conflict_is_stricter(self):
        local = self.variant(settings={"family_dns": False, "unlock_minutes": 10, "dork_guard": True})
        remote = self.variant(settings={"family_dns": True, "unlock_minutes": 2, "dork_guard": False})
        # family_dns: only local changed -> local; unlock: both changed -> min; dork: only remote -> remote
        merged = state.merge(self.BASE, local, remote)["settings"]
        self.assertFalse(merged["family_dns"])
        self.assertEqual(merged["unlock_minutes"], 2)
        self.assertFalse(merged["dork_guard"])
        both = state.merge(
            self.BASE,
            self.variant(settings={"family_dns": False, "unlock_minutes": 5, "dork_guard": True}),
            self.variant(settings={"family_dns": False, "unlock_minutes": 5, "dork_guard": True}),
        )["settings"]
        self.assertFalse(both["family_dns"])

    def test_first_sync_without_base_is_a_union(self):
        local = self.variant(rules=[["block", "a.com"]])
        remote = self.variant(rules=[["block", "z.com"]])
        merged = state.merge(None, local, remote)
        self.assertEqual({v for _, v in merged["rules"]}, {"a.com", "z.com"})

    def test_partner_newer_change_wins_and_counter_max(self):
        p_old = {"name": "Sam", "contact": "", "pin_hash": "h1", "totp_secret": "S", "pin_verify": "v1",
                 "changed_at": 100.0, "totp_last_counter": 5}
        p_local = dict(p_old, pin_hash="h2", pin_verify="v2", changed_at=200.0, totp_last_counter=7)
        p_remote = dict(p_old, pin_hash="h3", pin_verify="v3", changed_at=300.0, totp_last_counter=6)
        merged = state.merge(self.variant(partner=p_old), self.variant(partner=p_local), self.variant(partner=p_remote))
        self.assertEqual(merged["partner"]["pin_hash"], "h3")
        self.assertEqual(merged["partner"]["totp_last_counter"], 7)

    def test_partner_new_phone_takes_remote(self):
        p = {"name": "Sam", "contact": "", "pin_hash": "h", "totp_secret": "S", "pin_verify": "v", "changed_at": 1.0}
        self.assertEqual(state.merge(None, self.BASE, self.variant(partner=p))["partner"]["pin_hash"], "h")


class EndToEndTests(unittest.TestCase):
    """Two real phones syncing through the merge + apply path (no network)."""

    def test_second_phone_gets_everything_and_pin_works(self):
        a, b = phone(), phone()
        a.setup_partner("Sam", "", PIN)
        a.add_block("reddit.com")
        a.add_app("com.zhiliaoapp.musically", "TikTok")
        a.add_schedule("Night", 0b1111111, 22 * 60, 6 * 60, ["org.telegram.messenger"])
        snap_a = state.export(a)
        self.assertTrue(state.is_blank(state.export(b)))
        merged = state.merge(None, state.export(b), snap_a)
        b.apply_synced(merged)
        self.assertEqual([r.value for r in b.rules("block")], ["reddit.com"])
        self.assertEqual([x.package for x in b.blocked_apps()], ["com.zhiliaoapp.musically"])
        self.assertEqual(b.schedules()[0].name, "Night")
        self.assertTrue(b.is_setup)
        self.assertFalse(b.tampered, "applying a sync must keep the tamper seal valid")
        with self.assertRaises(Locked):  # the ratchet now protects phone B too
            b.add_allow("x.com")
        self.assertEqual(b.unlock(PIN), "pin")
        # offline PIN check file was re-signed with B's own seal key
        payload = (b.folder / "pin.verify").read_bytes()
        self.assertTrue(security.seal_ok(b.keys.get_key(), payload, (b.folder / "pin.verify.sig").read_text()))
        # B reopens cleanly
        b.conn.close()
        b2 = Guard(b.folder)
        self.assertFalse(b2.tampered)
        b2.conn.close()
        a.conn.close()

    def test_activity_imports_once_and_never_own(self):
        a, b = phone(), phone()
        a.add_block("reddit.com")
        snap = state.export(a)
        self.assertEqual(b.import_activity(snap["activity"]), len(snap["activity"]))
        self.assertEqual(b.import_activity(snap["activity"]), 0)  # no duplicates
        self.assertEqual(a.import_activity(snap["activity"]), 0)  # never its own
        self.assertIn(a.device_id, {row["device"] for row in b.history(50)})
        a.conn.close()
        b.conn.close()


if __name__ == "__main__":
    unittest.main()
