from fastapi import FastAPI, APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import json
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Set, Literal
from datetime import datetime, timedelta, timezone
import socketio
import asyncio
import requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
mongo_url = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_DAYS = int(os.environ.get('ACCESS_TOKEN_DAYS', '30'))

client = AsyncIOMotorClient(mongo_url)
db = client[DB_NAME]

app = FastAPI(title="WilWil API")
api_router = APIRouter(prefix="/api")
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
security = HTTPBearer(auto_error=False)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("wilwil")


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class RegisterIn(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=6, max_length=128)
    display_name: Optional[str] = None


class LoginIn(BaseModel):
    identifier: str
    password: str


class UserPublic(BaseModel):
    id: str
    username: str
    display_name: str
    email: EmailStr
    avatar_url: Optional[str] = None
    bio: Optional[str] = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class UpdateProfileIn(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None


class SendMessageIn(BaseModel):
    conversation_id: Optional[str] = None
    to_user_id: Optional[str] = None
    kind: Literal["text", "image", "audio", "video", "document", "link"] = "text"
    text: Optional[str] = None
    media_base64: Optional[str] = None  # data URI or raw base64
    link_url: Optional[str] = None
    duration_ms: Optional[int] = None


class MessagePublic(BaseModel):
    id: str
    conversation_id: str
    sender_id: str
    kind: str
    text: Optional[str] = None
    media_base64: Optional[str] = None
    link_url: Optional[str] = None
    duration_ms: Optional[int] = None
    created_at: str
    read: bool = False


class ConversationPublic(BaseModel):
    id: str
    other_user: UserPublic
    last_message: Optional[MessagePublic] = None
    unread_count: int = 0
    updated_at: str


class GroupCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    member_ids: List[str] = Field(default_factory=list, max_length=100)


class GroupUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    add_member_ids: List[str] = Field(default_factory=list, max_length=100)
    remove_member_ids: List[str] = Field(default_factory=list, max_length=100)


class BlockIn(BaseModel):
    user_id: str


class PushTokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=300)


class FriendRequestIn(BaseModel):
    user_id: str


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def create_token(user_id: str, username: str) -> str:
    now = now_utc()
    payload = {
        "sub": user_id,
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=ACCESS_TOKEN_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def user_to_public(u: dict) -> UserPublic:
    return UserPublic(
        id=u["id"],
        username=u["username"],
        display_name=u.get("display_name") or u["username"],
        email=u["email"],
        avatar_url=u.get("avatar_url"),
        bio=u.get("bio"),
    )


def conv_id_for(u1: str, u2: str) -> str:
    a, b = sorted([u1, u2])
    return f"{a}__{b}"


async def get_user_by_id(user_id: str) -> Optional[dict]:
    return await db.users.find_one({"id": user_id}, {"_id": 0})


async def are_friends(user_id: str, other_id: str) -> bool:
    return bool(await db.friendships.find_one({"users": {"$all": [user_id, other_id]}}, {"_id": 1}))


async def send_push_notification(user_ids: List[str], title: str, body: str):
    rows = await db.push_tokens.find({"user_id": {"$in": user_ids}}, {"_id": 0, "token": 1}).to_list(100)
    messages = [{"to": row["token"], "title": title, "body": body, "sound": "default"} for row in rows]
    if messages:
        await asyncio.to_thread(requests.post, "https://exp.host/--/api/v2/push/send", json=messages, timeout=10)


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def msg_to_public(m: dict) -> MessagePublic:
    return MessagePublic(
        id=m["id"],
        conversation_id=m["conversation_id"],
        sender_id=m["sender_id"],
        kind=m.get("kind", "text"),
        text=m.get("text"),
        media_base64=m.get("media_base64"),
        link_url=m.get("link_url"),
        duration_ms=m.get("duration_ms"),
        created_at=iso(m["created_at"]) if isinstance(m["created_at"], datetime) else m["created_at"],
        read=m.get("read", False),
    )


# ------------------------------------------------------------------
# WebSocket connection registry
# ------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, Set[WebSocket]] = {}

    def add(self, user_id: str, ws: WebSocket):
        self.active.setdefault(user_id, set()).add(ws)

    def remove(self, user_id: str, ws: WebSocket):
        if user_id in self.active:
            self.active[user_id].discard(ws)
            if not self.active[user_id]:
                self.active.pop(user_id, None)

    async def send_to_user(self, user_id: str, payload: dict):
        sockets = list(self.active.get(user_id, []))
        for ws in sockets:
            try:
                await ws.send_text(json.dumps(payload, default=str))
            except Exception:
                self.remove(user_id, ws)


manager = ConnectionManager()


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@api_router.get("/")
async def root():
    return {"service": "WilWil", "ok": True}


@api_router.post("/auth/register", response_model=TokenOut)
async def register(body: RegisterIn):
    email = body.email.lower().strip()
    username = body.username.lower().strip()

    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already exists")
    if await db.users.find_one({"username": username}):
        raise HTTPException(status_code=409, detail="Username already taken")

    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": email,
        "username": username,
        "display_name": (body.display_name or username).strip(),
        "password_hash": hash_password(body.password),
        "avatar_url": None,
        "bio": None,
        "created_at": now_utc(),
    }
    await db.users.insert_one(doc)
    token = create_token(user_id, username)
    return TokenOut(access_token=token, user=user_to_public(doc))


@api_router.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn):
    key = body.identifier.lower().strip()
    user = await db.users.find_one(
        {"$or": [{"email": key}, {"username": key}]}, {"_id": 0}
    )
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user["id"], user["username"])
    return TokenOut(access_token=token, user=user_to_public(user))


@api_router.get("/me", response_model=UserPublic)
async def me(user: dict = Depends(current_user)):
    return user_to_public(user)


@api_router.put("/me", response_model=UserPublic)
async def update_me(body: UpdateProfileIn, user: dict = Depends(current_user)):
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if updates:
        await db.users.update_one({"id": user["id"]}, {"$set": updates})
        user.update(updates)
    return user_to_public(user)


@api_router.get("/users/search", response_model=List[UserPublic])
async def search_users(q: str = Query(default="", min_length=0), user: dict = Depends(current_user)):
    blocked = await db.blocks.find({"owner_id": user["id"]}, {"_id": 0, "blocked_id": 1}).to_list(500)
    blocked_ids = [item["blocked_id"] for item in blocked]
    query = {"id": {"$nin": [user["id"], *blocked_ids]}}
    if q:
        query["$or"] = [
            {"username": {"$regex": q.lower(), "$options": "i"}},
            {"display_name": {"$regex": q, "$options": "i"}},
        ]
    cursor = db.users.find(query, {"_id": 0}).limit(50)
    users = [user_to_public(u) async for u in cursor]
    return users


@api_router.get("/users/{user_id}", response_model=UserPublic)
async def get_public_user(user_id: str, user: dict = Depends(current_user)):
    target = await get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return user_to_public(target)


@api_router.post("/friends/requests")
async def send_friend_request(body: FriendRequestIn, user: dict = Depends(current_user)):
    if body.user_id == user["id"] or not await get_user_by_id(body.user_id):
        raise HTTPException(status_code=400, detail="Invalid user")
    if await are_friends(user["id"], body.user_id):
        raise HTTPException(status_code=409, detail="Already friends")
    existing = await db.friend_requests.find_one({"from_id": user["id"], "to_id": body.user_id, "status": "pending"})
    if existing:
        raise HTTPException(status_code=409, detail="Request already sent")
    reverse = await db.friend_requests.find_one({"from_id": body.user_id, "to_id": user["id"], "status": "pending"})
    if reverse:
        await db.friend_requests.update_one({"_id": reverse["_id"]}, {"$set": {"status": "accepted"}})
        await db.friendships.update_one({"users": {"$all": [user["id"], body.user_id]}}, {"$set": {"users": sorted([user["id"], body.user_id])}}, upsert=True)
        return {"status": "accepted"}
    await db.friend_requests.insert_one({"from_id": user["id"], "to_id": body.user_id, "status": "pending", "created_at": now_utc()})
    await sio.emit("notification", {"type": "friend_request", "from_user_id": user["id"]}, room=body.user_id)
    return {"status": "pending"}


@api_router.get("/friends")
async def list_friends(user: dict = Depends(current_user)):
    rows = await db.friendships.find({"users": user["id"]}, {"_id": 0}).to_list(500)
    result = []
    for row in rows:
        other_id = next((item for item in row["users"] if item != user["id"]), None)
        other = await get_user_by_id(other_id) if other_id else None
        if other:
            result.append(user_to_public(other))
    return result


@api_router.get("/friends/requests")
async def list_friend_requests(user: dict = Depends(current_user)):
    rows = await db.friend_requests.find({"to_id": user["id"], "status": "pending"}, {"_id": 0}).to_list(500)
    result = []
    for row in rows:
        other = await get_user_by_id(row["from_id"])
        if other:
            result.append({"id": row["from_id"], "user": user_to_public(other), "created_at": iso(row["created_at"])})
    return result


@api_router.post("/friends/requests/{from_user_id}/accept")
async def accept_friend_request(from_user_id: str, user: dict = Depends(current_user)):
    request = await db.friend_requests.find_one_and_update({"from_id": from_user_id, "to_id": user["id"], "status": "pending"}, {"$set": {"status": "accepted"}})
    if not request:
        raise HTTPException(status_code=404, detail="Friend request not found")
    await db.friendships.update_one({"users": {"$all": [user["id"], from_user_id]}}, {"$set": {"users": sorted([user["id"], from_user_id])}}, upsert=True)
    await sio.emit("notification", {"type": "friend_accepted", "user_id": user["id"]}, room=from_user_id)
    return {"status": "accepted"}


@api_router.delete("/friends/{user_id}")
async def remove_friend(user_id: str, user: dict = Depends(current_user)):
    await db.friendships.delete_one({"users": {"$all": [user["id"], user_id]}})
    return {"ok": True}


@api_router.get("/conversations", response_model=List[ConversationPublic])
async def list_conversations(user: dict = Depends(current_user)):
    convs = db.conversations.find(
        {"participants": user["id"]}, {"_id": 0}
    ).sort("updated_at", -1)

    result: List[ConversationPublic] = []
    async for c in convs:
        other_id = next((p for p in c["participants"] if p != user["id"]), None)
        if not other_id:
            continue
        other = await get_user_by_id(other_id)
        if not other:
            continue
        # last message
        last = await db.messages.find_one(
            {"conversation_id": c["id"]}, {"_id": 0}, sort=[("created_at", -1)]
        )
        unread = await db.messages.count_documents(
            {"conversation_id": c["id"], "sender_id": {"$ne": user["id"]}, "read": False}
        )
        result.append(
            ConversationPublic(
                id=c["id"],
                other_user=user_to_public(other),
                last_message=msg_to_public(last) if last else None,
                unread_count=unread,
                updated_at=iso(c["updated_at"]) if isinstance(c["updated_at"], datetime) else c["updated_at"],
            )
        )
    return result


@api_router.post("/conversations/open", response_model=ConversationPublic)
async def open_conversation(payload: dict, user: dict = Depends(current_user)):
    other_id = payload.get("user_id")
    if not other_id or other_id == user["id"]:
        raise HTTPException(status_code=400, detail="Invalid target user")
    other = await get_user_by_id(other_id)
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    if not await are_friends(user["id"], other_id):
        raise HTTPException(status_code=403, detail="You can only chat with accepted friends")
    if await db.blocks.find_one({"$or": [{"owner_id": user["id"], "blocked_id": other_id}, {"owner_id": other_id, "blocked_id": user["id"]}]}):
        raise HTTPException(status_code=403, detail="User is blocked")
    cid = conv_id_for(user["id"], other_id)
    existing = await db.conversations.find_one({"id": cid}, {"_id": 0})
    if not existing:
        existing = {
            "id": cid,
            "participants": sorted([user["id"], other_id]),
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        await db.conversations.insert_one(dict(existing))
    return ConversationPublic(
        id=cid,
        other_user=user_to_public(other),
        last_message=None,
        unread_count=0,
        updated_at=iso(existing["updated_at"]) if isinstance(existing["updated_at"], datetime) else existing["updated_at"],
    )


@api_router.get("/conversations/{conversation_id}/messages", response_model=List[MessagePublic])
async def list_messages(conversation_id: str, user: dict = Depends(current_user)):
    conv = await db.conversations.find_one({"id": conversation_id}, {"_id": 0})
    if not conv:
        conv = await db.groups.find_one({"id": conversation_id}, {"_id": 0})
    if not conv or user["id"] not in conv["participants"]:
        raise HTTPException(status_code=404, detail="Conversation not found")
    cursor = db.messages.find({"conversation_id": conversation_id}, {"_id": 0}).sort("created_at", 1)
    msgs = [msg_to_public(m) async for m in cursor]
    # mark peer messages as read
    await db.messages.update_many(
        {"conversation_id": conversation_id, "sender_id": {"$ne": user["id"]}, "read": False},
        {"$set": {"read": True}},
    )
    return msgs


@api_router.post("/messages", response_model=MessagePublic)
async def send_message(body: SendMessageIn, user: dict = Depends(current_user)):
    # resolve conversation
    if body.conversation_id:
        conv = await db.conversations.find_one({"id": body.conversation_id}, {"_id": 0})
        is_group = False
        if not conv:
            conv = await db.groups.find_one({"id": body.conversation_id}, {"_id": 0})
            is_group = bool(conv)
        if not conv or user["id"] not in conv["participants"]:
            raise HTTPException(status_code=404, detail="Conversation not found")
        other_id = next((p for p in conv["participants"] if p != user["id"]), None)
    elif body.to_user_id:
        if body.to_user_id == user["id"]:
            raise HTTPException(status_code=400, detail="Cannot message self")
        other = await get_user_by_id(body.to_user_id)
        if not other:
            raise HTTPException(status_code=404, detail="User not found")
        other_id = body.to_user_id
        if not await are_friends(user["id"], other_id):
            raise HTTPException(status_code=403, detail="You can only chat with accepted friends")
        if await db.blocks.find_one({"$or": [{"owner_id": user["id"], "blocked_id": other_id}, {"owner_id": other_id, "blocked_id": user["id"]}]}):
            raise HTTPException(status_code=403, detail="User is blocked")
        cid = conv_id_for(user["id"], other_id)
        conv = await db.conversations.find_one({"id": cid}, {"_id": 0})
        if not conv:
            conv = {
                "id": cid,
                "participants": sorted([user["id"], other_id]),
                "created_at": now_utc(),
                "updated_at": now_utc(),
            }
            await db.conversations.insert_one(dict(conv))
    else:
        raise HTTPException(status_code=400, detail="conversation_id or to_user_id required")

    if body.kind == "text" and not (body.text and body.text.strip()):
        raise HTTPException(status_code=400, detail="Empty text")
    if body.kind in ("image", "audio", "video", "document") and not body.media_base64:
        raise HTTPException(status_code=400, detail="Missing media")
    if body.kind == "link" and not body.link_url:
        raise HTTPException(status_code=400, detail="Missing link")

    msg = {
        "id": str(uuid.uuid4()),
        "conversation_id": conv["id"],
        "sender_id": user["id"],
        "kind": body.kind,
        "text": body.text if body.kind == "text" else None,
        "media_base64": body.media_base64 if body.kind in ("image", "audio", "video", "document") else None,
        "link_url": body.link_url if body.kind == "link" else None,
        "duration_ms": body.duration_ms if body.kind == "audio" else None,
        "created_at": now_utc(),
        "read": False,
    }
    await db.messages.insert_one(dict(msg))
    collection = db.groups if body.conversation_id and is_group else db.conversations
    await collection.update_one({"id": conv["id"]}, {"$set": {"updated_at": now_utc()}})
    public = msg_to_public(msg)

    # broadcast via WebSocket to recipient AND back to sender for other devices
    payload = {"type": "message", "message": public.dict()}
    for recipient_id in conv["participants"]:
        if recipient_id != user["id"]:
            await manager.send_to_user(recipient_id, payload)
            await sio.emit("message", payload, room=recipient_id)
    await manager.send_to_user(user["id"], payload)
    await sio.emit("message", payload, room=user["id"])
    await send_push_notification([item for item in conv["participants"] if item != user["id"]], "Nouveau message", body.text or "Nouveau contenu partagé")

    return public


# ------------------------------------------------------------------
# WebSocket
# ------------------------------------------------------------------
@api_router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: Optional[str] = Query(default=None)):
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        payload = decode_token(token)
        user = await get_user_by_id(payload["sub"])
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    user_id = user["id"]
    manager.add(user_id, websocket)
    try:
        await websocket.send_text(json.dumps({"type": "ready", "user_id": user_id}))
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except Exception:
                continue
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        manager.remove(user_id, websocket)


# ------------------------------------------------------------------
# Startup / shutdown
# ------------------------------------------------------------------
@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.users.create_index("id", unique=True)
    await db.messages.create_index([("conversation_id", 1), ("created_at", 1)])
    await db.conversations.create_index("id", unique=True)
    await db.conversations.create_index("participants")
    await db.friendships.create_index("users", unique=True)
    await db.friend_requests.create_index([("from_id", 1), ("to_id", 1), ("status", 1)], unique=True)
    logger.info("WilWil API ready")


@app.on_event("shutdown")
async def on_shutdown():
    client.close()


app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@api_router.post("/groups", status_code=200)
async def create_group(body: GroupCreateIn, user: dict = Depends(current_user)):
    member_ids = sorted(set([user["id"], *body.member_ids]))
    members = await db.users.find({"id": {"$in": member_ids}}, {"_id": 0, "id": 1}).to_list(100)
    member_ids = [item["id"] for item in members]
    group = {"id": str(uuid.uuid4()), "name": body.name.strip(), "owner_id": user["id"], "participants": member_ids, "created_at": now_utc(), "updated_at": now_utc()}
    await db.groups.insert_one(group)
    public = {k: (iso(v) if isinstance(v, datetime) else v) for k, v in group.items()}
    await sio.emit("group_updated", public, room=group["id"])
    return public


@api_router.get("/groups")
async def list_groups(user: dict = Depends(current_user)):
    groups = db.groups.find({"participants": user["id"]}, {"_id": 0}).sort("updated_at", -1)
    return [{k: (iso(v) if isinstance(v, datetime) else v) for k, v in group.items()} async for group in groups]


@api_router.put("/groups/{group_id}")
async def update_group(group_id: str, body: GroupUpdateIn, user: dict = Depends(current_user)):
    group = await db.groups.find_one({"id": group_id, "participants": user["id"]}, {"_id": 0})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Only the group admin can manage members")
    updates = {}
    if body.name is not None:
        updates["name"] = body.name.strip()
    participants = sorted((set(group["participants"]) | set(body.add_member_ids)) - set(body.remove_member_ids) | {group["owner_id"]})
    updates["participants"] = participants
    updates["updated_at"] = now_utc()
    await db.groups.update_one({"id": group_id}, {"$set": updates})
    group.update(updates)
    public = {k: (iso(v) if isinstance(v, datetime) else v) for k, v in group.items()}
    await sio.emit("group_updated", public, room=group_id)
    return public


@api_router.delete("/groups/{group_id}")
async def delete_group(group_id: str, user: dict = Depends(current_user)):
    result = await db.groups.delete_one({"id": group_id, "owner_id": user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Group not found")
    await db.messages.delete_many({"conversation_id": group_id})
    await sio.emit("group_deleted", {"id": group_id}, room=group_id)
    return {"ok": True}


@api_router.post("/groups/{group_id}/leave")
async def leave_group(group_id: str, user: dict = Depends(current_user)):
    group = await db.groups.find_one({"id": group_id, "participants": user["id"]}, {"_id": 0})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] == user["id"]:
        raise HTTPException(status_code=400, detail="The admin must delete the group")
    await db.groups.update_one({"id": group_id}, {"$pull": {"participants": user["id"]}, "$set": {"updated_at": now_utc()}})
    await sio.emit("group_updated", {"id": group_id, "removed_user_id": user["id"]}, room=group_id)
    return {"ok": True}


@api_router.post("/blocks")
async def block_user(body: BlockIn, user: dict = Depends(current_user)):
    if body.user_id == user["id"] or not await get_user_by_id(body.user_id):
        raise HTTPException(status_code=400, detail="Invalid user")
    await db.blocks.update_one({"owner_id": user["id"], "blocked_id": body.user_id}, {"$set": {"created_at": now_utc()}}, upsert=True)
    await sio.emit("notification", {"type": "blocked", "user_id": user["id"]}, room=body.user_id)
    return {"ok": True, "user_id": body.user_id}


@api_router.post("/push-token")
async def save_push_token(body: PushTokenIn, user: dict = Depends(current_user)):
    await db.push_tokens.update_one({"user_id": user["id"], "token": body.token}, {"$set": {"updated_at": now_utc()}}, upsert=True)
    return {"ok": True}
    await db.push_tokens.create_index([("user_id", 1), ("token", 1)], unique=True)


@api_router.delete("/blocks/{user_id}")
async def unblock_user(user_id: str, user: dict = Depends(current_user)):
    await db.blocks.delete_one({"owner_id": user["id"], "blocked_id": user_id})
    return {"ok": True}


@api_router.get("/blocks")
async def list_blocked_users(user: dict = Depends(current_user)):
    rows = await db.blocks.find({"owner_id": user["id"]}, {"_id": 0}).to_list(500)
    users = []
    for row in rows:
        blocked = await get_user_by_id(row["blocked_id"])
        if blocked:
            users.append(user_to_public(blocked))
    return users


@sio.event
async def connect(sid, environ, auth):
    token = (auth or {}).get("token")
    try:
        user = await get_user_by_id(decode_token(token)["sub"])
    except Exception:
        return False
    await sio.save_session(sid, {"user_id": user["id"]})
    await sio.enter_room(sid, user["id"])
    await sio.emit("presence", {"user_id": user["id"], "online": True})


@sio.event
async def disconnect(sid):
    session = await sio.get_session(sid)
    if session:
        await sio.emit("presence", {"user_id": session["user_id"], "online": False})


@sio.event
async def join_conversation(sid, data):
    await sio.enter_room(sid, data.get("conversation_id"))


@sio.event
async def typing(sid, data):
    session = await sio.get_session(sid)
    await sio.emit("typing", {**data, "user_id": session["user_id"]}, room=data.get("conversation_id"), skip_sid=sid)


@sio.event
async def call_signal(sid, data):
    session = await sio.get_session(sid)
    await sio.emit("call_signal", {**data, "from_user_id": session["user_id"]}, room=data.get("to_user_id"))


@sio.event
async def call_end(sid, data):
    session = await sio.get_session(sid)
    await sio.emit("call_end", {"from_user_id": session["user_id"]}, room=data.get("to_user_id"))


app.include_router(api_router)
app = socketio.ASGIApp(sio, app)
