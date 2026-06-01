"""
Pyrogram userbot client — used by the WebUI to download large files (> 20 MB)
that exceed the Bot API limit.

Setup:
  1. Add API_ID and API_HASH to your .env (get from https://my.telegram.org)
  2. Run `python pyrogram_client.py` once to authenticate and create the session file.
  3. The session file (securebox.session) will be reused on every restart.
"""

import asyncio
import os
from dotenv import load_dotenv
from pyrogram import Client

load_dotenv()

API_ID   = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH", "")


def get_pyrogram_client() -> Client | None:
    """Return a Pyrogram Client instance, or None if credentials are missing."""
    if not API_ID or not API_HASH:
        return None
    return Client("securebox", api_id=API_ID, api_hash=API_HASH)


async def _auth():
    """Run once to generate the session file interactively."""
    client = get_pyrogram_client()
    if not client:
        print("ERROR: API_ID and API_HASH must be set in .env")
        return
    async with client:
        me = await client.get_me()
        print(f"Authenticated as: {me.first_name} (@{me.username})")
        print("Session saved to: securebox.session")


if __name__ == "__main__":
    asyncio.run(_auth())
