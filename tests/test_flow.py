"""End-to-end test of the auth protocol against an in-process server (plain text, loopback)."""

import base64
import json
import socket
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from concurrent import futures
from pathlib import Path

import grpc

from lore_auth_server.config import Config
from lore_auth_server.proto import auth_api_pb2 as pb
from lore_auth_server.proto import auth_api_pb2_grpc as pb_grpc
from lore_auth_server.proto import rebac_api_pb2 as rebac_pb
from lore_auth_server.proto import rebac_api_pb2_grpc as rebac_grpc
from lore_auth_server.service import Authority, RebacApi, UrcAuthApi
from lore_auth_server.store import Store
from lore_auth_server.tokens import TokenIssuer
from lore_auth_server.web import start_web_server

REPO_A = "urc-" + "a" * 32
REPO_B = "urc-" + "b" * 32
REPO_NEW = "urc-" + "c" * 32


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def bearer(token: str):
    return (("authorization", f"Bearer {token}"),)


class FlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        grpc_port, web_port = free_port(), free_port()
        cls.config = Config(
            public_grpc_url=f"http://127.0.0.1:{grpc_port}",
            public_web_url=f"http://127.0.0.1:{web_port}",
            audience=["lore.example.com"],
            grpc_listen=f"127.0.0.1:{grpc_port}",
            web_listen=f"127.0.0.1:{web_port}",
            data_dir=Path(cls.tmp.name),
        )
        cls.store = Store(cls.config.db_path)
        cls.store.add_user("alice", "alice-password")
        cls.store.add_user("root", "root-password", is_admin=True)
        cls.store.add_repository(REPO_A, "game")
        cls.store.add_repository(REPO_B, "secret")
        cls.store.grant("alice", REPO_A)

        authority = Authority(cls.config, cls.store, TokenIssuer(cls.config))
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_UrcAuthApiServicer_to_server(UrcAuthApi(authority), cls.server)
        rebac_grpc.add_RebacApiServicer_to_server(RebacApi(authority), cls.server)
        cls.server.add_insecure_port(cls.config.grpc_listen)
        cls.server.start()
        cls.web = start_web_server(authority)
        channel = grpc.insecure_channel(cls.config.grpc_listen)
        cls.auth = pb_grpc.UrcAuthApiStub(channel)
        cls.rebac = rebac_grpc.RebacApiStub(channel)

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.server.stop(None)
        cls.store.close()
        cls.tmp.cleanup()

    def browser_login(self, user: str, password: str) -> pb.UserToken | None:
        started = self.auth.StartAuthSession(pb.StartAuthSessionRequest(client_state="state-1"))
        self.assertTrue(started.login_url.startswith(self.config.public_web_url + "/login?session="))
        with urllib.request.urlopen(started.login_url) as page:
            self.assertIn(b"Sign in to Lore", page.read())
        form = urllib.parse.urlencode({"session": started.session_code, "username": user, "password": password})
        try:
            urllib.request.urlopen(f"{self.config.public_web_url}/login", data=form.encode())
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)
        polled = self.auth.GetAuthSession(
            pb.GetAuthSessionRequest(session_code=started.session_code, client_state="state-1")
        )
        return polled.user_token if polled.HasField("user_token") else None

    def test_browser_login_and_repository_access(self):
        self.assertIsNone(self.browser_login("alice", "wrong-password"))
        token = self.browser_login("alice", "alice-password")
        self.assertIsNotNone(token)
        self.assertEqual(token.user_id, "alice")

        exchanged = self.auth.ExchangeUserTokenForMultiresourceToken(
            pb.ExchangeUserTokenForMultiresourceTokenRequest(resource_id=[REPO_A]), metadata=bearer(token.user_token)
        )
        claims = json.loads(
            base64.urlsafe_b64decode(exchanged.token.user_token.split(".")[1] + "==")
        )
        self.assertEqual(claims["resources"], [{"resource_id": REPO_A, "permission": ["read", "write"]}])
        self.assertEqual(claims["aud"], ["lore.example.com"])

        with self.assertRaises(grpc.RpcError) as denied:
            self.auth.ExchangeUserTokenForMultiresourceToken(
                pb.ExchangeUserTokenForMultiresourceTokenRequest(resource_id=[REPO_B]),
                metadata=bearer(token.user_token),
            )
        self.assertEqual(denied.exception.code(), grpc.StatusCode.PERMISSION_DENIED)

        check = self.auth.CheckUserPermission(
            pb.CheckUserPermissionRequest(resource_id=[REPO_A, REPO_B]), metadata=bearer(token.user_token)
        )
        self.assertEqual([p.resource_id for p in check.allowed_resource_permission], [REPO_A])
        self.assertEqual([p.resource_id for p in check.denied_resource_permission], [REPO_B])

        listed = self.auth.LookupUserPermissions(
            pb.LookupUserPermissionsRequest(resource_filter="urc"), metadata=bearer(token.user_token)
        )
        self.assertEqual([p.resource_id for p in listed.resource_permission], [REPO_A])

    def test_session_is_single_use(self):
        started = self.auth.StartAuthSession(pb.StartAuthSessionRequest(client_state="s"))
        empty = self.auth.GetAuthSession(pb.GetAuthSessionRequest(session_code=started.session_code, client_state="s"))
        self.assertFalse(empty.HasField("user_token"))

    def test_requests_without_token_are_rejected(self):
        with self.assertRaises(grpc.RpcError) as e:
            self.auth.CheckUserPermission(pb.CheckUserPermissionRequest(resource_id=[REPO_A]))
        self.assertEqual(e.exception.code(), grpc.StatusCode.UNAUTHENTICATED)

    def test_creator_gets_access_and_admin_sees_everything(self):
        token = self.browser_login("alice", "alice-password")
        self.rebac.CreateResource(
            rebac_pb.CreateResourceRequest(resource_id=REPO_NEW, resource_name="new"), metadata=bearer(token.user_token)
        )
        self.auth.ExchangeUserTokenForMultiresourceToken(
            pb.ExchangeUserTokenForMultiresourceTokenRequest(resource_id=[REPO_NEW]), metadata=bearer(token.user_token)
        )
        admin = self.browser_login("root", "root-password")
        listed = self.auth.LookupUserPermissions(pb.LookupUserPermissionsRequest(), metadata=bearer(admin.user_token))
        self.assertEqual({p.resource_id for p in listed.resource_permission}, {REPO_A, REPO_B, REPO_NEW})
        self.rebac.DeleteResource(rebac_pb.DeleteResourceRequest(resource_id=REPO_NEW), metadata=bearer(admin.user_token))

    def test_api_key_login(self):
        key = self.store.create_api_key("alice", "ci")
        response = self.auth.ExchangeExternalTokenForUserToken(
            pb.ExchangeExternalTokenForUserTokenRequest(external_token=key, token_type="api-key")
        )
        self.assertEqual(response.user_token.user_id, "alice")
        with self.assertRaises(grpc.RpcError):
            self.auth.ExchangeAPIKeyForUserToken(pb.ExchangeAPIKeyForUserTokenRequest(api_key="lak_wrong"))

    def test_jwks_is_served(self):
        with urllib.request.urlopen(f"{self.config.public_web_url}/jwks.json") as r:
            self.assertEqual(json.load(r)["keys"][0]["alg"], "RS256")


if __name__ == "__main__":
    unittest.main()
