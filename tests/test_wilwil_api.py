"""End-to-end backend tests for WilWil messaging API."""
import os
import json
import uuid
import time
import base64
import asyncio
from urllib.parse import urlparse

import pytest
import requests
import websockets

BASE_URL = os.environ['EXPO_PUBLIC_BACKEND_URL'].rstrip('/') if os.environ.get('EXPO_PUBLIC_BACKEND_URL') else None
if not BASE_URL:
    # Fallback to reading frontend/.env
    from pathlib import Path
    envp = Path('/app/frontend/.env')
    if envp.exists():
        for line in envp.read_text().splitlines():
            if line.startswith('EXPO_PUBLIC_BACKEND_URL='):
                BASE_URL = line.split('=', 1)[1].strip().strip('"').rstrip('/')
API = f"{BASE_URL}/api"

ALICE = {"email": "alice@wilwil.com", "username": "alice", "password": "password123", "display_name": "Alice"}
BOB = {"email": "bob@wilwil.com", "username": "bob", "password": "password123", "display_name": "Bob"}


def _ensure_user(u):
    r = requests.post(f"{API}/auth/register", json=u, timeout=15)
    if r.status_code == 200:
        return r.json()
    # already exists -> login
    r = requests.post(f"{API}/auth/login", json={"identifier": u["email"], "password": u["password"]}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    return r.json()


@pytest.fixture(scope="session")
def tokens():
    a = _ensure_user(ALICE)
    b = _ensure_user(BOB)
    return {"alice": a, "bob": b}


def _h(tok):
    return {"Authorization": f"Bearer {tok}"}


# ------------------------ Health ------------------------
def test_root():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    assert r.json().get("ok") is True


# ------------------------ Auth ------------------------
def test_register_returns_token_and_user(tokens):
    a = tokens["alice"]
    assert "access_token" in a and a["access_token"]
    assert a["user"]["username"] == "alice"
    assert a["user"]["email"] == "alice@wilwil.com"


def test_login_with_username(tokens):
    r = requests.post(f"{API}/auth/login", json={"identifier": "bob", "password": "password123"}, timeout=10)
    assert r.status_code == 200, r.text
    assert r.json()["user"]["username"] == "bob"


def test_login_with_email(tokens):
    r = requests.post(f"{API}/auth/login", json={"identifier": "alice@wilwil.com", "password": "password123"}, timeout=10)
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "alice@wilwil.com"


def test_login_bad_password():
    r = requests.post(f"{API}/auth/login", json={"identifier": "alice", "password": "wrong"}, timeout=10)
    assert r.status_code == 401


def test_register_duplicate(tokens):
    r = requests.post(f"{API}/auth/register", json=ALICE, timeout=10)
    assert r.status_code == 409


def test_me_requires_auth():
    r = requests.get(f"{API}/me", timeout=10)
    assert r.status_code in (401, 403)


def test_me_returns_current_user(tokens):
    r = requests.get(f"{API}/me", headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


# ------------------------ Users search ------------------------
def test_search_excludes_self(tokens):
    r = requests.get(f"{API}/users/search?q=", headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200
    ids = [u["id"] for u in r.json()]
    assert tokens["alice"]["user"]["id"] not in ids


def test_search_filters(tokens):
    r = requests.get(f"{API}/users/search?q=bob", headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200
    usernames = [u["username"] for u in r.json()]
    assert "bob" in usernames


# ------------------------ Conversations ------------------------
@pytest.fixture(scope="session")
def conversation(tokens):
    r = requests.post(
        f"{API}/conversations/open",
        json={"user_id": tokens["bob"]["user"]["id"]},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_open_conversation_idempotent(tokens, conversation):
    r = requests.post(
        f"{API}/conversations/open",
        json={"user_id": tokens["bob"]["user"]["id"]},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 200
    assert r.json()["id"] == conversation["id"]


def test_open_conversation_rejects_self(tokens):
    r = requests.post(
        f"{API}/conversations/open",
        json={"user_id": tokens["alice"]["user"]["id"]},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 400


# ------------------------ Messages ------------------------
def test_send_text_message(tokens, conversation):
    body = {"conversation_id": conversation["id"], "kind": "text", "text": f"hello {uuid.uuid4().hex[:6]}"}
    r = requests.post(f"{API}/messages", json=body, headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["text"] == body["text"]
    assert m["sender_id"] == tokens["alice"]["user"]["id"]
    assert m["kind"] == "text"


def test_send_empty_text_rejected(tokens, conversation):
    r = requests.post(
        f"{API}/messages",
        json={"conversation_id": conversation["id"], "kind": "text", "text": "   "},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 400


def test_send_image_message(tokens, conversation):
    tiny = base64.b64encode(b"\x89PNG\r\n\x1a\n").decode()
    r = requests.post(
        f"{API}/messages",
        json={"conversation_id": conversation["id"], "kind": "image",
              "media_base64": f"data:image/png;base64,{tiny}"},
        headers=_h(tokens["bob"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 200
    assert r.json()["kind"] == "image"
    assert r.json()["media_base64"].startswith("data:image/png;base64,")


def test_send_audio_message(tokens, conversation):
    tiny = base64.b64encode(b"RIFFxxxxWAVE").decode()
    r = requests.post(
        f"{API}/messages",
        json={"conversation_id": conversation["id"], "kind": "audio",
              "media_base64": f"data:audio/m4a;base64,{tiny}", "duration_ms": 1500},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 200
    assert r.json()["kind"] == "audio"
    assert r.json()["duration_ms"] == 1500


def test_send_message_by_to_user_id(tokens):
    r = requests.post(
        f"{API}/messages",
        json={"to_user_id": tokens["bob"]["user"]["id"], "kind": "text", "text": "via to_user_id"},
        headers=_h(tokens["alice"]["access_token"]),
        timeout=10,
    )
    assert r.status_code == 200


def test_send_message_requires_auth(conversation):
    r = requests.post(f"{API}/messages",
                     json={"conversation_id": conversation["id"], "kind": "text", "text": "hi"},
                     timeout=10)
    assert r.status_code in (401, 403)


def test_non_participant_cannot_send(tokens, conversation):
    # register a third user
    third = {"email": f"eve_{uuid.uuid4().hex[:6]}@wilwil.com",
             "username": f"eve{uuid.uuid4().hex[:6]}",
             "password": "password123", "display_name": "Eve"}
    reg = requests.post(f"{API}/auth/register", json=third, timeout=10).json()
    r = requests.post(f"{API}/messages",
                     json={"conversation_id": conversation["id"], "kind": "text", "text": "intrude"},
                     headers=_h(reg["access_token"]), timeout=10)
    assert r.status_code == 404


def test_list_conversations_shows_last_and_unread(tokens, conversation):
    # bob sends a fresh message so alice has unread
    txt = f"unread {uuid.uuid4().hex[:6]}"
    requests.post(f"{API}/messages",
                  json={"conversation_id": conversation["id"], "kind": "text", "text": txt},
                  headers=_h(tokens["bob"]["access_token"]), timeout=10)
    r = requests.get(f"{API}/conversations", headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200
    conv = next((c for c in r.json() if c["id"] == conversation["id"]), None)
    assert conv is not None
    assert conv["other_user"]["username"] == "bob"
    assert conv["last_message"] is not None
    assert conv["unread_count"] >= 1


def test_list_messages_marks_peer_read(tokens, conversation):
    # After alice lists messages, bob's messages should be marked read (read receipts)
    r = requests.get(f"{API}/conversations/{conversation['id']}/messages",
                     headers=_h(tokens["alice"]["access_token"]), timeout=10)
    assert r.status_code == 200
    msgs = r.json()
    assert isinstance(msgs, list)
    # NOTE: the endpoint returns messages fetched before marking as read,
    # so the returned payload may still show read=False for peer messages.
    # A subsequent GET (which the UI does anyway) must show them read via unread_count=0.
    r_again = requests.get(f"{API}/conversations/{conversation['id']}/messages",
                           headers=_h(tokens["alice"]["access_token"]), timeout=10)
    peer_unread = [m for m in r_again.json() if m["sender_id"] != tokens["alice"]["user"]["id"] and not m["read"]]
    assert peer_unread == []
    # And unread count on conversation list should now be 0 for alice
    r2 = requests.get(f"{API}/conversations", headers=_h(tokens["alice"]["access_token"]), timeout=10)
    conv = next((c for c in r2.json() if c["id"] == conversation["id"]), None)
    assert conv["unread_count"] == 0


def test_list_messages_forbidden_for_outsider(tokens, conversation):
    third = {"email": f"mallory_{uuid.uuid4().hex[:6]}@wilwil.com",
             "username": f"mal{uuid.uuid4().hex[:6]}",
             "password": "password123"}
    reg = requests.post(f"{API}/auth/register", json=third, timeout=10).json()
    r = requests.get(f"{API}/conversations/{conversation['id']}/messages",
                     headers=_h(reg["access_token"]), timeout=10)
    assert r.status_code == 404


# ------------------------ WebSocket ------------------------
def _ws_url():
    p = urlparse(BASE_URL)
    scheme = "wss" if p.scheme == "https" else "ws"
    return f"{scheme}://{p.netloc}/api/ws"


@pytest.mark.asyncio
async def test_ws_authenticated_broadcasts_new_message(tokens, conversation):
    ws_url = f"{_ws_url()}?token={tokens['bob']['access_token']}"
    async with websockets.connect(ws_url, open_timeout=10) as ws:
        ready = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        assert ready.get("type") == "ready"
        # Alice sends a message; Bob's WS should receive it
        payload = {"conversation_id": conversation["id"], "kind": "text",
                   "text": f"ws-hello {uuid.uuid4().hex[:6]}"}
        r = requests.post(f"{API}/messages", json=payload,
                          headers=_h(tokens["alice"]["access_token"]), timeout=10)
        assert r.status_code == 200
        got = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        assert got["type"] == "message"
        assert got["message"]["text"] == payload["text"]


@pytest.mark.asyncio
async def test_ws_rejects_missing_token():
    with pytest.raises(Exception):
        async with websockets.connect(_ws_url(), open_timeout=10) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)


@pytest.mark.asyncio
async def test_ws_rejects_bad_token():
    with pytest.raises(Exception):
        async with websockets.connect(f"{_ws_url()}?token=notatoken", open_timeout=10) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)
