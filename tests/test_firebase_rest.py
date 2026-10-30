import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from guardpulse.sync.firebase import Config, Conflict, Firebase, FirebaseError, Session  # noqa: E402

CONFIG = Config(api_key="KEY", project_id="gp-proj", web_client_id="web")


class Recorder:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        return self.responses.pop(0)


def session(expires_at=10_000.0):
    return Session("uid1", "e@x.com", "IDTOK", "REFTOK", expires_at)


class FirebaseRestTests(unittest.TestCase):
    def test_sign_in_with_google(self):
        http = Recorder((200, {"localId": "uid1", "email": "e@x.com", "idToken": "I", "refreshToken": "R", "expiresIn": "3600"}))
        s = Firebase(CONFIG, http=http, clock=lambda: 1000).sign_in_with_google("GOOGLE_ID_TOKEN")
        method, url, body, _ = http.calls[0]
        self.assertEqual(method, "POST")
        self.assertIn("accounts:signInWithIdp?key=KEY", url)
        self.assertIn("id_token=GOOGLE_ID_TOKEN", body["postBody"])
        self.assertIn("providerId=google.com", body["postBody"])
        self.assertEqual((s.uid, s.id_token, s.refresh_token, s.expires_at), ("uid1", "I", "R", 4600))

    def test_sign_in_refused(self):
        http = Recorder((400, {"error": {"message": "INVALID_IDP_RESPONSE"}}))
        with self.assertRaisesRegex(FirebaseError, "INVALID_IDP_RESPONSE"):
            Firebase(CONFIG, http=http).sign_in_with_google("bad")

    def test_refresh_only_when_near_expiry(self):
        http = Recorder((200, {"id_token": "NEW", "refresh_token": "R2", "user_id": "uid1", "expires_in": "3600"}))
        fb = Firebase(CONFIG, http=http, clock=lambda: 9_900.0)
        same = Firebase(CONFIG, http=Recorder(), clock=lambda: 0).fresh(session())
        self.assertEqual(same.id_token, "IDTOK")  # far from expiry: no call
        fresh = fb.fresh(session())  # 100 s left: refreshed
        self.assertEqual((fresh.id_token, fresh.refresh_token), ("NEW", "R2"))
        _, url, body, headers = http.calls[0]
        self.assertIn("securetoken.googleapis.com/v1/token?key=KEY", url)
        self.assertEqual(body["grant_type"], "refresh_token")
        self.assertEqual(headers["Content-Type"], "application/x-www-form-urlencoded")

    def test_get_state(self):
        http = Recorder(
            (404, {"error": {"status": "NOT_FOUND"}}),
            (200, {"fields": {"blob": {"stringValue": "B"}, "rev": {"integerValue": "3"}}, "updateTime": "T1"}),
        )
        fb = Firebase(CONFIG, http=http)
        self.assertEqual(fb.get_state(session()), (None, 0, None))
        self.assertEqual(fb.get_state(session()), ("B", 3, "T1"))
        _, url, _, headers = http.calls[1]
        self.assertTrue(url.endswith("/projects/gp-proj/databases/(default)/documents/users/uid1/guardpulse/state"))
        self.assertEqual(headers["Authorization"], "Bearer IDTOK")

    def test_put_preconditions(self):
        http = Recorder((200, {"updateTime": "T2"}), (200, {"updateTime": "T3"}))
        fb = Firebase(CONFIG, http=http)
        self.assertEqual(fb.put_state(session(), "B", 1, None), "T2")
        self.assertIn("currentDocument.exists=false", http.calls[0][1])
        fb.put_state(session(), "B", 2, "2026-10-30T10:00:00.123456Z")
        self.assertIn("currentDocument.updateTime=2026-10-30T10%3A00%3A00.123456Z", http.calls[1][1])
        self.assertEqual(http.calls[1][2]["fields"]["rev"], {"integerValue": "2"})

    def test_put_conflict(self):
        http = Recorder((400, {"error": {"status": "FAILED_PRECONDITION", "message": "stale"}}))
        with self.assertRaises(Conflict):
            Firebase(CONFIG, http=http).put_state(session(), "B", 2, "T1")

    def test_config_load(self):
        self.assertFalse(Config.load(Path("does-not-exist.json")).ready)
        self.assertTrue(CONFIG.ready)


if __name__ == "__main__":
    unittest.main()
