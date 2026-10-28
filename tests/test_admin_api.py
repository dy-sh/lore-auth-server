"""Tests of the admin API against an in-process web listener (plain text, loopback)."""

import base64
import dataclasses
import json
import re
import socket
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from lore_auth_server.config import Config, load_config
from lore_auth_server.service import Authority
from lore_auth_server.store import Store
from lore_auth_server.tokens import TokenIssuer
from lore_auth_server.web import start_web_server

REPO_A = "urc-" + "a" * 32
REPO_B = "urc-" + "b" * 32
REPO_C = "urc-" + "c" * 32
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AdminApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.base_config = Config(
            public_grpc_url="http://127.0.0.1:1",
            public_web_url="http://127.0.0.1:1",
            audience=["lore.example.com"],
            data_dir=Path(cls.key_dir.name),
        )
        cls.issuer = TokenIssuer(cls.base_config)  # key generation is slow, share it

    @classmethod
    def tearDownClass(cls):
        cls.key_dir.cleanup()

    def setUp(self):
        self.store, self.url = self.start_server()
        self.store.add_user("root", "root-password", "Root", is_admin=True)
        self.store.add_user("alice", "alice-password")
        self.store.add_user("bob", "bob-password")
        self.store.add_repository(REPO_A, "game", creator="alice")
        self.store.add_repository(REPO_B, "secret")
        self.store.grant("alice", REPO_A)
        self.root = self.token("root")
        self.alice = self.token("alice")

    def start_server(self, **overrides) -> tuple[Store, str]:
        data = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        port = free_port()
        config = dataclasses.replace(
            self.base_config,
            public_web_url=f"http://127.0.0.1:{port}",
            web_listen=f"127.0.0.1:{port}",
            data_dir=Path(data.name),
            **overrides,
        )
        store = Store(config.db_path)
        web = start_web_server(Authority(config, store, self.issuer))
        self.addCleanup(data.cleanup)
        self.addCleanup(store.close)
        self.addCleanup(web.server_close)
        self.addCleanup(web.shutdown)
        return store, config.public_web_url

    def token(self, name: str) -> str:
        return self.issuer.user_token(self.store.get_user(name))[0]

    def call(self, method, path, token=None, body=None, raw=None, content_type="application/json", url=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request((url or self.url) + path, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", content_type)
        if token is not None:
            request.add_header("Authorization", token if " " in token else f"Bearer {token}")
        try:
            with OPENER.open(request) as response:
                status, payload, headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as e:
            status, payload, headers = e.code, e.read(), e.headers
        is_json = headers.get("Content-Type") == "application/json"
        return status, (json.loads(payload) if is_json else payload or None), headers

    def assertError(self, result, status: int, code: str):
        self.assertEqual(result[0], status, result[1])
        self.assertEqual(result[1]["error"]["code"], code)
        self.assertTrue(result[1]["error"]["message"])

    # Discovery and configuration

    def test_discovery(self):
        status, body, headers = self.call("GET", "/.well-known/lore-admin")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(
            body,
            {"protocol": "lore-admin", "version": 1, "base": "/api/v1",
             "features": ["users", "grants", "repositories", "api-keys"]},
        )
        self.assertError(self.call("POST", "/.well-known/lore-admin", body={}), 405, "method_not_allowed")

    def test_disabled_api_is_absent(self):
        store, url = self.start_server(admin_api=False)
        store.add_user("admin", "admin-password", is_admin=True)
        token = self.issuer.user_token(store.get_user("admin"))[0]
        self.assertEqual(self.call("GET", "/.well-known/lore-admin", url=url)[0], 404)
        self.assertEqual(self.call("GET", "/api/v1/me", token, url=url)[0], 404)
        self.assertEqual(self.call("DELETE", "/api/v1/users/admin", token, url=url)[0], 404)
        self.assertIsNotNone(store.get_user("admin"))
        with OPENER.open(url + "/health") as r:
            self.assertEqual(r.read(), b"ok")

    def test_config_option(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "config.toml"
            base = '[server]\npublic_grpc_url = "https://a:1"\npublic_web_url = "https://a:2"\n{}' \
                   '[tokens]\naudience = ["a"]\n'
            path.write_text(base.format(""))
            self.assertTrue(load_config(path).admin_api)
            path.write_text(base.format("admin_api = false\n"))
            self.assertFalse(load_config(path).admin_api)
            path.write_text(base.format('admin_api = "no"\n'))
            with self.assertRaises(ValueError):
                load_config(path)

    # Authentication

    def test_missing_or_malformed_authorization(self):
        result = self.call("GET", "/api/v1/me")
        self.assertError(result, 401, "unauthenticated")
        self.assertEqual(result[2]["WWW-Authenticate"], "Bearer")
        self.assertError(self.call("GET", "/api/v1/me", "Basic cm9vdDpyb290LXBhc3N3b3Jk"), 401, "unauthenticated")
        self.assertError(self.call("GET", "/api/v1/me", "Bearer "), 401, "unauthenticated")
        result = self.call("GET", "/api/v1/users", "not-a-token")
        self.assertError(result, 401, "unauthenticated")
        self.assertIn("invalid_token", result[2]["WWW-Authenticate"])

    def test_forged_expired_access_and_orphaned_tokens_are_rejected(self):
        header, claims, signature = self.alice.split(".")
        forged = json.loads(base64.urlsafe_b64decode(claims + "=="))
        forged["sub"] = "root"
        forged_claims = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
        forged_token = f"{header}.{forged_claims}.{signature}"
        self.assertError(self.call("GET", "/api/v1/users", forged_token), 401, "unauthenticated")
        self.assertError(self.call("GET", "/api/v1/me", "W10.W10.W10"), 401, "unauthenticated")

        with mock.patch.object(self.issuer.config, "user_token_ttl_hours", -1):
            expired = self.token("root")
        self.assertError(self.call("GET", "/api/v1/me", expired), 401, "unauthenticated")

        access, _ = self.issuer.access_token(
            self.store.get_user("root"), [{"resource_id": REPO_A, "permission": ["read", "write"]}]
        )
        self.assertError(self.call("GET", "/api/v1/me", access), 401, "unauthenticated")

        bob = self.token("bob")
        self.store.remove_user("bob")
        self.assertError(self.call("GET", "/api/v1/me", bob), 401, "unauthenticated")

    def test_repeated_invalid_tokens_are_throttled(self):
        for _ in range(5):
            self.assertError(self.call("GET", "/api/v1/me", "bad.token.value"), 401, "unauthenticated")
        result = self.call("GET", "/api/v1/me", "bad.token.value")
        self.assertError(result, 429, "too_many_requests")
        self.assertEqual(result[2]["Retry-After"], "300")
        # Expired and valid tokens are not throttled.
        with mock.patch.object(self.issuer.config, "user_token_ttl_hours", -1):
            expired = self.token("root")
        self.assertError(self.call("GET", "/api/v1/me", expired), 401, "unauthenticated")
        self.assertEqual(self.call("GET", "/api/v1/me", self.root)[0], 200)

    def test_non_admin_is_forbidden_except_me(self):
        status, body, _ = self.call("GET", "/api/v1/me", self.alice)
        self.assertEqual((status, body), (200, {"name": "alice", "displayName": "alice", "admin": False}))
        requests = [
            ("GET", "/api/v1/users", None),
            ("POST", "/api/v1/users", {"name": "eve", "password": "eve-password", "admin": True}),
            ("PATCH", "/api/v1/users/alice", {"admin": True}),
            ("PUT", "/api/v1/users/root/password", {"password": "taken-over"}),
            ("DELETE", "/api/v1/users/root", None),
            ("GET", "/api/v1/grants", None),
            ("PUT", "/api/v1/grants", {"user": "alice", "repository": "*"}),
            ("DELETE", "/api/v1/grants", {"user": "alice", "repository": "game"}),
            ("GET", "/api/v1/repositories", None),
            ("GET", "/api/v1/api-keys", None),
            ("POST", "/api/v1/api-keys", {"user": "root"}),
            ("DELETE", "/api/v1/api-keys/root", None),
        ]
        for method, path, body in requests:
            with self.subTest(method=method, path=path):
                self.assertError(self.call(method, path, self.alice, body), 403, "forbidden")
        self.assertIsNone(self.store.get_user("eve"))
        self.assertFalse(self.store.get_user("alice").is_admin)
        self.assertEqual(self.store.grants_of("alice"), [REPO_A])
        self.assertIsNotNone(self.store.check_password("root", "root-password"))

    def test_disabled_user_is_refused(self):
        self.store.add_user("dave", "dave-password", is_admin=True)
        dave = self.token("dave")
        self.assertEqual(self.call("GET", "/api/v1/me", dave)[0], 200)
        self.store.set_disabled("dave", True)
        self.assertError(self.call("GET", "/api/v1/me", dave), 403, "user_disabled")
        self.assertError(self.call("GET", "/api/v1/users", dave), 403, "user_disabled")
        self.assertError(self.call("DELETE", "/api/v1/users/bob", dave), 403, "user_disabled")
        self.assertIsNotNone(self.store.get_user("bob"))

    # Endpoints

    def test_me(self):
        status, body, _ = self.call("GET", "/api/v1/me", self.root)
        self.assertEqual((status, body), (200, {"name": "root", "displayName": "Root", "admin": True}))

    def test_users(self):
        status, body, _ = self.call("GET", "/api/v1/users", self.root)
        self.assertEqual(status, 200)
        self.assertEqual(
            body["users"],
            [
                {"name": "alice", "displayName": "alice", "admin": False, "disabled": False},
                {"name": "bob", "displayName": "bob", "admin": False, "disabled": False},
                {"name": "root", "displayName": "Root", "admin": True, "disabled": False},
            ],
        )

        created = {"name": "carol", "password": "carol-password", "displayName": " Carol Smith "}
        status, body, _ = self.call("POST", "/api/v1/users", self.root, created)
        self.assertEqual(status, 201)
        self.assertEqual(body, {"name": "carol", "displayName": "Carol Smith", "admin": False, "disabled": False})
        self.assertIsNotNone(self.store.check_password("carol", "carol-password"))
        status, body, _ = self.call("POST", "/api/v1/users", self.root,
                                    {"name": "dave", "password": "dave-password", "admin": True})
        self.assertEqual((status, body["admin"], body["displayName"]), (201, True, "dave"))

        self.assertError(self.call("POST", "/api/v1/users", self.root, {"name": "carol", "password": "carol-password"}),
                         409, "conflict")
        for bad in (
            {"name": "bad name", "password": "long-enough"},
            {"name": "erin", "password": "short"},
            {"name": "erin"},
            {"password": "long-enough"},
            {"name": "erin", "password": "long-enough", "admin": "yes"},
            {"name": "erin", "password": "long-enough", "role": "admin"},
            {"name": "erin", "password": "long-enough", "displayName": "x" * 129},
            {"name": "erin", "password": "long-enough", "displayName": "line\nbreak"},
        ):
            with self.subTest(body=bad):
                self.assertError(self.call("POST", "/api/v1/users", self.root, bad), 400, "invalid_request")
        self.assertIsNone(self.store.get_user("erin"))

        status, body, _ = self.call("PATCH", "/api/v1/users/carol", self.root,
                                    {"displayName": "Carol S.", "admin": True, "disabled": True})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"name": "carol", "displayName": "Carol S.", "admin": True, "disabled": True})
        self.assertIsNone(self.store.check_password("carol", "carol-password"))  # disabled
        status, body, _ = self.call("PATCH", "/api/v1/users/carol", self.root, {"disabled": False, "displayName": ""})
        self.assertEqual((status, body["disabled"], body["displayName"]), (200, False, "carol"))
        self.assertError(self.call("PATCH", "/api/v1/users/carol", self.root, {}), 400, "invalid_request")
        self.assertError(self.call("PATCH", "/api/v1/users/carol", self.root, {"admin": 1}), 400, "invalid_request")
        self.assertError(self.call("PATCH", "/api/v1/users/nobody", self.root, {"admin": True}), 404, "not_found")

        new_password = {"password": "new-password"}
        self.assertEqual(self.call("PUT", "/api/v1/users/carol/password", self.root, new_password)[0], 204)
        self.assertIsNotNone(self.store.check_password("carol", "new-password"))
        self.assertIsNone(self.store.check_password("carol", "carol-password"))
        self.assertError(self.call("PUT", "/api/v1/users/carol/password", self.root, {"password": "short"}),
                         400, "invalid_request")
        self.assertError(self.call("PUT", "/api/v1/users/carol/password", self.root, {}), 400, "invalid_request")
        self.assertError(self.call("PUT", "/api/v1/users/nobody/password", self.root, {"password": "new-password"}),
                         404, "not_found")

        self.store.create_api_key("carol")
        self.assertEqual(self.call("DELETE", "/api/v1/users/carol", self.root)[0], 204)
        self.assertIsNone(self.store.get_user("carol"))
        self.assertEqual(self.store.api_keys("carol"), [])
        self.assertError(self.call("DELETE", "/api/v1/users/carol", self.root), 404, "not_found")

    def test_admin_cannot_lock_themselves_out(self):
        self.assertError(self.call("PATCH", "/api/v1/users/root", self.root, {"admin": False}), 409, "conflict")
        self.assertError(self.call("PATCH", "/api/v1/users/root", self.root, {"disabled": True}), 409, "conflict")
        self.assertError(self.call("DELETE", "/api/v1/users/root", self.root), 409, "conflict")
        root = self.store.get_user("root")
        self.assertTrue(root.is_admin and not root.disabled)
        status, body, _ = self.call("PATCH", "/api/v1/users/root", self.root, {"displayName": "Admin", "admin": True})
        self.assertEqual((status, body["displayName"]), (200, "Admin"))
        new_password = {"password": "new-password"}
        self.assertEqual(self.call("PUT", "/api/v1/users/root/password", self.root, new_password)[0], 204)

    def test_grants(self):
        game = {"user": "alice", "repository": "a" * 32, "repositoryName": "game"}
        self.assertEqual(self.call("GET", "/api/v1/grants", self.root)[:2], (200, {"grants": [game]}))

        status, body, _ = self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": "secret"})
        self.assertEqual((status, body), (200, {"user": "bob", "repository": "b" * 32, "repositoryName": "secret"}))
        status, body, _ = self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": "*"})
        self.assertEqual((status, body), (200, {"user": "bob", "repository": "*", "repositoryName": None}))
        unregistered = {"user": "bob", "repository": "urc-" + "d" * 32}
        status, body, _ = self.call("PUT", "/api/v1/grants", self.root, unregistered)
        self.assertEqual((status, body["repository"], body["repositoryName"]), (200, "d" * 32, None))
        self.assertEqual(self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": "secret"})[0], 200)
        self.assertEqual(sorted(self.store.grants_of("bob")), sorted([REPO_B, "urc-*", "urc-" + "d" * 32]))

        status, body, _ = self.call("GET", "/api/v1/grants?user=bob", self.root)
        self.assertEqual([g["repository"] for g in body["grants"]], ["*", "b" * 32, "d" * 32])
        self.assertEqual(self.call("GET", "/api/v1/grants?repository=game", self.root)[1], {"grants": [game]})
        status, body, _ = self.call("GET", f"/api/v1/grants?repository={'a' * 32}&user=bob", self.root)
        self.assertEqual(body, {"grants": []})
        status, body, _ = self.call("GET", "/api/v1/grants?repository=*", self.root)
        self.assertEqual([g["user"] for g in body["grants"]], ["bob"])
        self.assertError(self.call("GET", "/api/v1/grants?user=nobody", self.root), 404, "not_found")
        self.assertError(self.call("GET", "/api/v1/grants?repository=nothing", self.root), 404, "not_found")
        self.assertError(self.call("GET", "/api/v1/grants?owner=bob", self.root), 400, "invalid_request")
        self.assertError(self.call("GET", "/api/v1/grants?user=bob&user=alice", self.root), 400, "invalid_request")
        self.assertError(self.call("GET", "/api/v1/grants?user=", self.root), 400, "invalid_request")

        self.assertError(self.call("PUT", "/api/v1/grants", self.root, {"user": "nobody", "repository": "game"}),
                         404, "not_found")
        self.assertError(self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": "nothing"}),
                         404, "not_found")
        self.assertError(self.call("PUT", "/api/v1/grants", self.root, {"user": "bob"}), 400, "invalid_request")
        self.assertError(self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": ""}),
                         400, "invalid_request")
        self.store.add_repository(REPO_C, "game")
        self.assertError(self.call("PUT", "/api/v1/grants", self.root, {"user": "bob", "repository": "game"}),
                         409, "conflict")

        secret = {"user": "bob", "repository": "secret"}
        self.assertEqual(self.call("DELETE", "/api/v1/grants", self.root, secret)[0], 204)
        self.assertEqual(self.call("DELETE", "/api/v1/grants", self.root, secret)[0], 204)  # idempotent
        self.assertEqual(self.call("DELETE", "/api/v1/grants", self.root, {"user": "bob", "repository": "*"})[0], 204)
        self.assertEqual(self.store.grants_of("bob"), ["urc-" + "d" * 32])
        self.assertError(self.call("DELETE", "/api/v1/grants", self.root, {"user": "nobody", "repository": "*"}),
                         404, "not_found")

    def test_repositories(self):
        status, body, _ = self.call("GET", "/api/v1/repositories", self.root)
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {"repositories": [
                {"id": "a" * 32, "name": "game", "creator": "alice"},
                {"id": "b" * 32, "name": "secret", "creator": None},
            ]},
        )

    def test_api_keys(self):
        self.assertEqual(self.call("GET", "/api/v1/api-keys", self.root)[1], {"apiKeys": []})
        status, created, _ = self.call("POST", "/api/v1/api-keys", self.root, {"user": "bob", "label": "build server"})
        self.assertEqual(status, 201)
        self.assertTrue(created["key"].startswith("lak_"))
        self.assertEqual((created["user"], created["label"]), ("bob", "build server"))
        self.assertRegex(created["id"], r"^[0-9a-f]{12}$")
        self.assertRegex(created["createdAt"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(self.store.user_for_api_key(created["key"]).name, "bob")
        self.assertEqual(self.call("POST", "/api/v1/api-keys", self.root, {"user": "alice"})[0], 201)

        status, body, _ = self.call("GET", "/api/v1/api-keys", self.root)
        self.assertEqual([k["user"] for k in body["apiKeys"]], ["alice", "bob"])
        listed = body["apiKeys"][1]
        self.assertEqual(listed, {k: created[k] for k in ("id", "user", "label", "createdAt")})
        self.assertNotIn(created["key"], json.dumps(body))
        self.assertEqual(len(self.call("GET", "/api/v1/api-keys?user=bob", self.root)[1]["apiKeys"]), 1)
        self.assertError(self.call("GET", "/api/v1/api-keys?user=nobody", self.root), 404, "not_found")

        self.assertError(self.call("POST", "/api/v1/api-keys", self.root, {"user": "nobody"}), 404, "not_found")
        self.assertError(self.call("POST", "/api/v1/api-keys", self.root, {"user": "bob", "label": "a\tb"}),
                         400, "invalid_request")
        self.assertError(self.call("POST", "/api/v1/api-keys", self.root, {"label": "x"}), 400, "invalid_request")

        self.assertEqual(self.call("DELETE", "/api/v1/api-keys/bob", self.root)[:2], (200, {"revoked": 1}))
        self.assertIsNone(self.store.user_for_api_key(created["key"]))
        self.assertEqual(self.call("DELETE", "/api/v1/api-keys/bob", self.root)[:2], (200, {"revoked": 0}))
        self.assertEqual(len(self.store.api_keys("alice")), 1)
        self.assertError(self.call("DELETE", "/api/v1/api-keys/nobody", self.root), 404, "not_found")

    # Requests

    def test_request_validation(self):
        users = "/api/v1/users"
        self.assertError(self.call("POST", users, self.root, raw=b"{not json"), 400, "invalid_request")
        self.assertError(self.call("POST", users, self.root, raw=b"[1, 2]"), 400, "invalid_request")
        self.assertError(self.call("POST", users, self.root, raw=b"\xff\xfe"), 400, "invalid_request")
        self.assertError(self.call("POST", users, self.root, raw=b"[" * 5000 + b"]" * 5000), 413, "payload_too_large")
        self.assertError(self.call("POST", users, self.root, raw=b"[" * 4000 + b"]" * 4000), 400, "invalid_request")
        form = self.call("POST", users, self.root, raw=b"name=x", content_type="application/x-www-form-urlencoded")
        self.assertError(form, 415, "unsupported_media_type")
        big = {"name": "erin", "password": "x" * 9000}
        self.assertError(self.call("POST", users, self.root, big), 413, "payload_too_large")
        self.assertIsNone(self.store.get_user("erin"))
        status, body, _ = self.call(
            "POST", users, self.root, raw=json.dumps({"name": "erin", "password": "erin-password"}).encode(),
            content_type="application/json; charset=utf-8",
        )
        self.assertEqual(status, 201)

        self.assertError(self.call("GET", "/api/v1/nothing", self.root), 404, "not_found")
        self.assertError(self.call("GET", "/api/v1", self.root), 404, "not_found")
        self.assertError(self.call("GET", "/api/v1/users/alice/password", self.root), 405, "method_not_allowed")
        result = self.call("DELETE", users, self.root)
        self.assertError(result, 405, "method_not_allowed")
        self.assertEqual(result[2]["Allow"], "GET, POST")
        self.assertEqual(self.call("PUT", "/login", self.root, {})[0], 404)

    def test_admin_actions_are_logged_without_secrets(self):
        with self.assertLogs("lore_auth_server", level="DEBUG") as logs:
            self.call("POST", "/api/v1/users", self.root, {"name": "carol", "password": "first-secret-pw"})
            self.call("PUT", "/api/v1/users/carol/password", self.root, {"password": "second-secret-pw"})
            key = self.call("POST", "/api/v1/api-keys", self.root, {"user": "carol"})[1]["key"]
            self.call("PUT", "/api/v1/grants", self.root, {"user": "carol", "repository": "game"})
            self.call("DELETE", "/api/v1/users/carol", self.root)
        output = "\n".join(logs.output)
        for secret in ("first-secret-pw", "second-secret-pw", key, self.root):
            self.assertNotIn(secret, output)
        for action in ("created user carol", "changed the password of user carol", "created API key",
                       "granted carol access to " + "a" * 32, "deleted user carol"):
            self.assertTrue(re.search(rf"admin root from 127\.0\.0\.1: {re.escape(action)}", output), action)


if __name__ == "__main__":
    unittest.main()
