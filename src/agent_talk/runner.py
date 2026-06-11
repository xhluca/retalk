"""Poll-loop entrypoint: publish keys, optionally send, then receive
forever. Run directly: `python runner.py` (see README for examples).

Env config:
AUTO_REPLY     set to 1 to auto-acknowledge every received message
BROKER_URL     e.g. https://broker.example.com/mcp (or http://host:8766/mcp)
               — must match the broker's BROKER_AUDIENCE exactly, since
               request signatures are bound to it
PICKLE_SECRET  secret unlocking local private-key storage
STORE          local SQLite path
NICKNAME       cosmetic display name (not unique)
PEER           the peer's user ID (fingerprint), needed to send
PEER_NAME      optional: your local (trusted) display name for PEER;
               without it, the peer's self-chosen nickname shows as ~name
PEER_PIN       optional: the peer's full identity key for an explicit pin
               (the ID is already a self-verifying fingerprint of it)
SEND           optional message to send to PEER on startup

Key maintenance (optional):
MIN_OTKS           replenish when unclaimed one-time keys drop below this (default 20)
OTK_BATCH          batch size for initial publish and replenishment (default 100)
FALLBACK_MAX_AGE   rotate the fallback key after this many seconds (default 86400)
MAINTAIN_INTERVAL  seconds between maintenance checks (default 60)
"""

import asyncio
import os
import time

from .user import User


async def run(nickname_default: str, store_default: str,
              auto_reply: bool = False):
    peer = os.environ.get("PEER")
    pins = {}
    names = {}
    if peer and os.environ.get("PEER_PIN"):
        pins[peer] = os.environ["PEER_PIN"]
    if peer and os.environ.get("PEER_NAME"):
        names[peer] = os.environ["PEER_NAME"]
    batch = int(os.environ.get("OTK_BATCH", "100"))
    min_otks = int(os.environ.get("MIN_OTKS", "20"))
    fallback_max_age = float(os.environ.get("FALLBACK_MAX_AGE", "86400"))
    maintain_interval = float(os.environ.get("MAINTAIN_INTERVAL", "60"))

    user = User(
        broker_url=os.environ["BROKER_URL"],
        pickle_secret=os.environ["PICKLE_SECRET"],
        nickname=os.environ.get("NICKNAME", nickname_default),
        store=os.environ.get("STORE", store_default),
        pins=pins,
        names=names,
    )
    me = user.nickname
    await user.publish(n=batch)
    print(f"[{me}] user id (give this to your peer; it is address + pin):")
    print(f"[{me}]   {user.user_id()}")

    if os.environ.get("SEND"):
        if not peer:
            raise SystemExit("SEND requires PEER (the peer's user id)")
        await user.send(peer, os.environ["SEND"])
        print(f"[{me}] sent to {peer}: {os.environ['SEND']}")

    print(f"[{me}] polling for messages (ctrl-c to stop)...")
    last_maintain = time.monotonic()
    while True:
        for sender, nick, text in await user.receive():
            print(f"[{me}] {nick or sender}: {text}")
            if auto_reply:
                reply = f"ack: {text}"
                await user.send(sender, reply)
                print(f"[{me}] replied to {nick or sender}: {reply}")
        if time.monotonic() - last_maintain > maintain_interval:
            status = await user.maintain(min_otks=min_otks, batch=batch,
                                          fallback_max_age=fallback_max_age)
            if status["replenished"] or status["fallback_rotated"]:
                print(f"[{me}] key maintenance: {status}")
            last_maintain = time.monotonic()
        await asyncio.sleep(2)


def main(nickname_default: str = "user", store_default: str = "user.db",
         auto_reply: bool = False):
    asyncio.run(run(nickname_default, store_default, auto_reply))


def cli():
    main(auto_reply=os.environ.get("AUTO_REPLY", "").lower() in ("1", "true", "yes"))


if __name__ == "__main__":
    cli()
