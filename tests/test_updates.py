import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse import safety, updates  # noqa: E402
from guardpulse.guard import Guard  # noqa: E402

PIN = "4826"


def release_json(tag="v0.4.0", assets=None, **extra):
    data = {
        "tag_name": tag,
        "name": f"GuardPulse {tag}",
        "body": "Notes",
        "html_url": f"https://github.com/3th4n-J/GuardPulse/releases/tag/{tag}",
        "assets": assets
        if assets is not None
        else [
            {"name": "GuardPulse-0.4.0.apk.sha256", "browser_download_url": "https://x/sum", "size": 90},
            {"name": "other.apk", "browser_download_url": "https://x/other.apk", "size": 5},
            {"name": "GuardPulse-0.4.0.apk", "browser_download_url": "https://x/gp.apk", "size": 94_000_000},
        ],
    }
    data.update(extra)
    return data


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(updates.parse_version("v0.4.0"), (0, 4, 0))
        self.assertEqual(updates.parse_version("1.2"), (1, 2))
        self.assertEqual(updates.parse_version("v1.0.0-beta.2"), (1, 0, 0))
        self.assertEqual(updates.parse_version("nightly"), ())

    def test_is_newer(self):
        self.assertTrue(updates.is_newer("v0.4.0", "0.3.2"))
        self.assertTrue(updates.is_newer("v0.10.0", "0.9.9"))  # numeric, not string compare
        self.assertFalse(updates.is_newer("v0.3.2", "0.3.2"))
        self.assertFalse(updates.is_newer("v0.3.1", "0.3.2"))
        self.assertFalse(updates.is_newer("v1.0", "1.0.0"))
        self.assertFalse(updates.is_newer("garbage", "0.1.0"))


class ReleaseParsingTests(unittest.TestCase):
    def test_prefers_guardpulse_apk(self):
        r = updates.parse_release(release_json())
        self.assertEqual(r.apk_name, "GuardPulse-0.4.0.apk")
        self.assertEqual(r.apk_url, "https://x/gp.apk")
        self.assertEqual(r.version, "0.4.0")

    def test_no_apk_still_links_page(self):
        r = updates.parse_release(release_json(assets=[]))
        self.assertIsNone(r.apk_url)
        self.assertIn("/releases/tag/v0.4.0", r.page_url)

    def test_drafts_and_prereleases_ignored(self):
        self.assertIsNone(updates.parse_release(release_json(draft=True)))
        self.assertIsNone(updates.parse_release(release_json(prerelease=True)))


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # mimic Android: <app>/files/data is today's folder
        self.folder = self.root / "files" / "data"
        self.folder.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def make_guard(self) -> Guard:
        g = Guard(self.folder)
        return g

    def populated(self) -> Guard:
        g = self.make_guard()
        g.setup_partner("Sam", "", PIN)
        g.add_block("bad.com")
        g.add_app("com.reddit.frontpage", "Reddit")
        return g

    def test_snapshot_is_consistent_and_pruned(self):
        g = self.populated()
        for i in range(5):
            g.snapshot(f"t{i}")
        snaps = safety.snapshots(self.folder)
        self.assertEqual(len(snaps), safety.KEEP_SNAPSHOTS)
        self.assertTrue(all(s.with_suffix(".key").exists() for s in snaps))
        g.conn.close()

    def test_missing_db_restored_from_snapshot_without_tamper(self):
        g = self.populated()
        g.snapshot("before-0.4.0")
        g.conn.close()
        (self.folder / "guardpulse.db").unlink()
        for side in ("guardpulse.db-wal", "guardpulse.db-shm"):
            (self.folder / side).unlink(missing_ok=True)
        g2 = self.make_guard()
        self.assertIn("snapshot", g2.recovered)
        self.assertTrue(g2.is_setup)
        self.assertEqual([r.value for r in g2.rules("block")], ["bad.com"])
        self.assertFalse(g2.tampered, "restored DB + key must still pass the seal check")
        self.assertEqual(g2.unlock(PIN), "pin")
        g2.conn.close()

    def test_storage_move_picks_up_old_folder(self):
        # an older build kept data in <app>/app_flutter (Selah's failure mode)
        old = self.root / "app_flutter"
        old.mkdir()
        g = Guard(old)
        g.setup_partner("Sam", "", PIN)
        g.add_block("bad.com")
        g.conn.close()
        g2 = self.make_guard()  # new build looks in files/data
        self.assertIn("moved data", g2.recovered)
        self.assertEqual([r.value for r in g2.rules("block")], ["bad.com"])
        self.assertFalse(g2.tampered)
        self.assertTrue((old / "guardpulse.db").exists(), "original must be left in place")
        g2.conn.close()

    def test_recovery_never_overwrites_existing_data(self):
        g = self.populated()
        g.conn.close()
        old = self.root / "app_flutter"
        old.mkdir()
        shutil.copy2(self.folder / "guardpulse.db", old / "guardpulse.db")
        self.assertIsNone(safety.recover_if_missing(self.folder))

    def test_fresh_install_starts_empty(self):
        g = self.make_guard()
        self.assertIsNone(g.recovered)
        self.assertFalse(g.is_setup)
        g.conn.close()

    def test_corrupt_candidate_is_skipped(self):
        old = self.root / "app_flutter"
        old.mkdir()
        (old / "guardpulse.db").write_bytes(b"not a database")
        self.assertIsNone(safety.recover_if_missing(self.folder))

    def test_version_tracking(self):
        g = self.make_guard()
        self.assertIsNone(g.note_app_version("0.3.2"))  # first run records silently
        self.assertIsNone(g.note_app_version("0.3.2"))
        self.assertEqual(g.note_app_version("0.4.0"), "0.3.2")
        self.assertEqual(g.history(1)[0]["action"], "app.updated")
        g.conn.close()


if __name__ == "__main__":
    unittest.main()
