import logging
import os
import subprocess
import asyncio
import math
from datetime import datetime
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import (
    Message, InlineQuery,
    InlineQueryResultArticle, InlineQueryResultCachedAudio,
    InlineQueryResultCachedDocument, InlineQueryResultCachedPhoto,
    InlineQueryResultCachedSticker, InlineQueryResultCachedVideo,
    InlineQueryResultCachedVoice,
    CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton,
    InputTextMessageContent, BotCommand, FSInputFile,
)
from aiogram.enums.parse_mode import ParseMode
from aiogram.client.bot import DefaultBotProperties
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from dotenv import load_dotenv

from sticker import add_sticker_to_pack, list_sticker_packs

load_dotenv()

BOT_TOKEN          = os.getenv("BOT_TOKEN")
MONGO_URI          = os.getenv("MONGO_URI")
STORAGE_CHANNEL_ID = os.getenv("STORAGE_CHANNEL_ID")
WEBUI_SECRET_KEY   = os.getenv("WEBUI_SECRET_KEY", "securebox-secret-key-change-me")
WEBUI_PORT         = int(os.getenv("WEBUI_PORT", 8080))

# Pyrogram credentials (needed for large-file download in webui)
API_ID   = os.getenv("API_ID", "")    # from my.telegram.org
API_HASH = os.getenv("API_HASH", "")  # from my.telegram.org

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp  = Dispatcher()

mongo_client       = AsyncIOMotorClient(MONGO_URI)
db                 = mongo_client["file_store_bot"]
files_collection   = db["files"]
folders_collection = db["folders"]
settings_collection= db["settings"]   # stores per-user webui password hash


# ── FSM States ────────────────────────────────────────────────────────────────

class RenameFile(StatesGroup):
    waiting_for_new_name = State()

class AddFolder(StatesGroup):
    waiting_for_folders = State()

class FolderPagination(StatesGroup):
    selecting_folder = State()

class SetPassword(StatesGroup):
    waiting_for_password = State()

class CreateFolder(StatesGroup):
    waiting_for_folder_name = State()
    waiting_for_parent = State()


# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_size(n):
    if n is None: return "Unknown"
    for unit in ("B","KB","MB","GB"):
        if n < 1024: return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.2f} TB"


# ── /start ────────────────────────────────────────────────────────────────────

async def start_cmd(message: Message):
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📂 Explore Files", switch_inline_query_current_chat="")],
        [InlineKeyboardButton(text="📁 My Folders",    callback_data="show_folders")],
    ])
    await message.answer(
        "🔒 <b>SecureBox</b>\n\n"
        "Send me any file and I'll store it securely.\n"
        "Use <b>/folders</b> to browse, <b>/setpassword</b> to protect your WebUI.",
        reply_markup=markup
    )


# ── /setpassword ──────────────────────────────────────────────────────────────

async def setpassword_cmd(message: Message, state: FSMContext):
    await state.set_state(SetPassword.waiting_for_password)
    await message.answer(
        "🔑 <b>Set WebUI Password</b>\n\nSend your new password (it will be saved securely):"
    )

async def setpassword_handler(message: Message, state: FSMContext):
    import hashlib
    uid = message.from_user.id
    pw  = message.text.strip()
    if not pw:
        await message.reply("❌ Password cannot be empty.")
        return
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    await settings_collection.update_one(
        {"user_id": uid},
        {"$set": {"webui_password_hash": pw_hash}},
        upsert=True
    )
    await message.reply(
        "✅ <b>WebUI password set!</b>\n\n"
        f"Access your file manager at:\n<code>http://your-server:{WEBUI_PORT}</code>",
        parse_mode="HTML"
    )
    await state.clear()


# ── /createfolder ─────────────────────────────────────────────────────────────

async def createfolder_cmd(message: Message, state: FSMContext):
    await state.set_state(CreateFolder.waiting_for_folder_name)
    await message.answer("📁 <b>Create Folder</b>\n\nSend the folder name:")

async def createfolder_name_handler(message: Message, state: FSMContext):
    uid  = message.from_user.id
    name = message.text.strip()
    if not name:
        await message.reply("❌ Name cannot be empty.")
        return
    await state.update_data(folder_name=name)
    # Ask for parent folder
    folders_cursor = folders_collection.find({"user_id": uid, "parent": None}).sort("name", 1)
    root_folders   = [doc["name"] for doc in await folders_cursor.to_list(length=50)]
    keyboard = [[InlineKeyboardButton(text="📂 Root (no parent)", callback_data="set_parent:__root__")]]
    for f in root_folders:
        keyboard.append([InlineKeyboardButton(text=f"📁 {f}", callback_data=f"set_parent:{f}")])
    await state.set_state(CreateFolder.waiting_for_parent)
    await message.answer(
        "📁 Where should this folder go?",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard)
    )

async def set_parent_callback(callback_query: CallbackQuery, state: FSMContext):
    uid    = callback_query.from_user.id
    parent = callback_query.data.split(":", 1)[1]
    if parent == "__root__":
        parent = None
    data = await state.get_data()
    name = data.get("folder_name", "Unnamed")
    # Check duplicate
    existing = await folders_collection.find_one({"user_id": uid, "name": name, "parent": parent})
    if existing:
        await callback_query.message.edit_text(f"⚠️ Folder <b>{name}</b> already exists.", parse_mode="HTML")
    else:
        await folders_collection.insert_one({
            "user_id": uid, "name": name, "parent": parent,
            "created_at": datetime.utcnow()
        })
        loc = f"in 📁 {parent}" if parent else "at root"
        await callback_query.message.edit_text(
            f"✅ Folder <b>{name}</b> created {loc}.", parse_mode="HTML"
        )
    await state.clear()
    await callback_query.answer()


# ── /folders ──────────────────────────────────────────────────────────────────

async def folders_cmd(message: Message, state: FSMContext):
    await show_folders_at(message, None, state)

async def show_folders_at(message_or_cb, parent, state):
    if isinstance(message_or_cb, CallbackQuery):
        uid = message_or_cb.from_user.id
    else:
        uid = message_or_cb.from_user.id

    folders_cursor = folders_collection.find(
        {"user_id": uid, "parent": parent}
    ).sort("name", 1)
    folders = await folders_cursor.to_list(length=100)

    if not folders:
        text = "📭 No folders yet.\nUse /createfolder to make one."
        if isinstance(message_or_cb, CallbackQuery):
            await message_or_cb.message.edit_text(text)
            await message_or_cb.answer()
        else:
            await message_or_cb.answer(text)
        return

    keyboard = []
    for f in folders:
        fname = f["name"]
        keyboard.append([InlineKeyboardButton(
            text=f"📁 {fname}", callback_data=f"folder_menu:{fname}"
        )])
    if parent:
        keyboard.append([InlineKeyboardButton(text="⬅️ Back", callback_data="show_folders")])

    markup = InlineKeyboardMarkup(inline_keyboard=keyboard)
    text   = f"📁 <b>{'Folders in ' + parent if parent else 'Your Folders'}</b>:"

    if isinstance(message_or_cb, CallbackQuery):
        await message_or_cb.message.edit_text(text, reply_markup=markup, parse_mode="HTML")
        await message_or_cb.answer()
    else:
        await message_or_cb.answer(text, reply_markup=markup, parse_mode="HTML")


# ── File saving ───────────────────────────────────────────────────────────────

async def forward_to_storage_channel(message: Message):
    try:
        fwd = await message.forward(STORAGE_CHANNEL_ID)
        return fwd.message_id
    except Exception as e:
        logging.error(f"Forward error: {e}")
        return None

async def save_file(message: Message):
    file_id = file_name = file_type = None
    file_size = None
    message_date = message.date.strftime("%Y-%m-%d %H:%M:%S")

    if message.document:
        file_id, file_name, file_size, file_type = (
            message.document.file_id, message.document.file_name,
            message.document.file_size, "document"
        )
    elif message.video:
        file_id, file_name, file_size, file_type = (
            message.video.file_id, "video.mp4", message.video.file_size, "video"
        )
    elif message.audio:
        file_id, file_name, file_size, file_type = (
            message.audio.file_id, message.audio.file_name or "audio.mp3",
            message.audio.file_size, "audio"
        )
    elif message.photo:
        file_id, file_name, file_size, file_type = (
            message.photo[-1].file_id, "photo.jpg",
            message.photo[-1].file_size, "photo"
        )
    elif message.voice:
        file_id, file_name, file_size, file_type = (
            message.voice.file_id, "voice.ogg", message.voice.file_size, "voice"
        )
    elif message.video_note:
        file_id, file_name, file_size, file_type = (
            message.video_note.file_id, "video_note.mp4",
            message.video_note.file_size, "video_note"
        )

    if not file_id:
        return

    uid = message.from_user.id
    existing = await files_collection.find_one({"file_id": file_id, "user_id": uid})

    if existing:
        mongo_id = str(existing["_id"])
        buttons  = _file_buttons(mongo_id, existing.get("file_type"))
        await message.reply(
            "⚠️ <b>Already saved.</b>\n"
            f"<b>Name:</b> {existing['file_name']}\n"
            f"<b>Type:</b> {existing['file_type']}\n"
            f"<b>Size:</b> {fmt_size(existing.get('file_size'))}\n"
            f"<b>Date:</b> {message_date}",
            reply_markup=buttons
        )
    else:
        storage_mid = await forward_to_storage_channel(message)
        res = await files_collection.insert_one({
            "user_id": uid, "file_id": file_id,
            "file_name": file_name, "file_size": file_size,
            "file_type": file_type, "folders": [],
            "message_date": message.date,
            "storage_message_id": storage_mid,
            "storage_channel_id": int(STORAGE_CHANNEL_ID),
        })
        mongo_id = str(res.inserted_id)
        buttons  = _file_buttons(mongo_id, file_type)
        await message.reply(
            "✅ <b>File saved!</b>\n"
            f"<b>Name:</b> {file_name}\n"
            f"<b>Type:</b> {file_type}\n"
            f"<b>Size:</b> {fmt_size(file_size)}\n"
            f"<b>Date:</b> {message_date}",
            reply_markup=buttons
        )

def _file_buttons(mongo_id, file_type):
    kb = [
        [InlineKeyboardButton(text="✏️ Rename",        callback_data=f"rename:{mongo_id}")],
        [InlineKeyboardButton(text="📁 Add to Folder", callback_data=f"addfolder:{mongo_id}")],
        [InlineKeyboardButton(text="🗑️ Delete",        callback_data=f"delete:{mongo_id}")],
    ]
    if file_type == "video":
        kb.append([InlineKeyboardButton(text="🔄 Convert to Video Note",
                                        callback_data=f"convert_video_note:{mongo_id}")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


# ── Inline query ──────────────────────────────────────────────────────────────

async def inline_query_handler(inline_query: InlineQuery):
    uid   = inline_query.from_user.id
    query = inline_query.query.lower()
    files = await files_collection.find({"user_id": uid}).to_list(length=50)
    results = []
    for f in files:
        folders_str = ", ".join(f.get("folders", [])) or "No folders"
        if query and query not in f["file_name"].lower() and \
           not any(query in fld.lower() for fld in f.get("folders", [])):
            continue
        desc = (f"{f.get('file_type','').capitalize()} | "
                f"{fmt_size(f.get('file_size'))} | {folders_str}")
        ftype = f.get("file_type")
        fid   = f.get("file_id")
        title = f.get("file_name")
        rid   = str(f["_id"])
        try:
            if ftype == "photo":
                results.append(InlineQueryResultCachedPhoto(id=rid,title=title,photo_file_id=fid,description=desc))
            elif ftype == "video":
                results.append(InlineQueryResultCachedVideo(id=rid,title=title,video_file_id=fid,description=desc))
            elif ftype == "audio":
                results.append(InlineQueryResultCachedAudio(id=rid,title=title,audio_file_id=fid))
            elif ftype == "voice":
                results.append(InlineQueryResultCachedVoice(id=rid,title=title,voice_file_id=fid))
            elif ftype == "sticker":
                results.append(InlineQueryResultCachedSticker(id=rid,sticker_file_id=fid))
            else:
                results.append(InlineQueryResultCachedDocument(id=rid,title=title,document_file_id=fid,description=desc))
        except Exception:
            results.append(InlineQueryResultArticle(id=rid,title=title,
                input_message_content=InputTextMessageContent(message_text=title),description=desc))
    await bot.answer_inline_query(inline_query.id, results=results, cache_time=0)


# ── Callbacks ─────────────────────────────────────────────────────────────────

async def callback_query_handler(callback_query: CallbackQuery, state: FSMContext):
    data = callback_query.data
    uid  = callback_query.from_user.id

    # ── show_folders ──
    if data == "show_folders":
        await show_folders_at(callback_query, None, state)

    # ── folder_menu ──
    elif data.startswith("folder_menu:"):
        folder = data.split(":", 1)[1]
        # check if it has subfolders
        sub_cursor = folders_collection.find({"user_id": uid, "parent": folder})
        subs = await sub_cursor.to_list(length=50)
        kb = [
            [InlineKeyboardButton(text="🔎 Search files here", switch_inline_query_current_chat=folder)],
            [InlineKeyboardButton(text="✏️ Rename", callback_data=f"rename_folder:{folder}"),
             InlineKeyboardButton(text="🗑️ Delete", callback_data=f"delete_folder:{folder}")],
        ]
        if subs:
            kb.insert(0,[InlineKeyboardButton(text="📂 Open Subfolders", callback_data=f"open_subfolder:{folder}")])
        kb.append([InlineKeyboardButton(text="⬅️ Back", callback_data="show_folders")])
        await callback_query.message.edit_text(
            f"📁 <b>{folder}</b>\nChoose an action:",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=kb),
            parse_mode="HTML"
        )
        await callback_query.answer()

    elif data.startswith("open_subfolder:"):
        parent = data.split(":", 1)[1]
        await show_folders_at(callback_query, parent, state)

    # ── rename folder ──
    elif data.startswith("rename_folder:"):
        folder = data.split(":", 1)[1]
        await state.set_state(FolderPagination.selecting_folder)
        await state.update_data(folder=folder)
        await callback_query.message.reply(f"Send new name for folder <b>{folder}</b>:", parse_mode="HTML")
        await callback_query.answer()

    # ── delete folder ──
    elif data.startswith("delete_folder:"):
        folder = data.split(":", 1)[1]
        await files_collection.update_many(
            {"user_id": uid, "folders": folder}, {"$pull": {"folders": folder}}
        )
        await folders_collection.delete_one({"user_id": uid, "name": folder})
        # also delete subfolders
        await folders_collection.delete_many({"user_id": uid, "parent": folder})
        await callback_query.message.edit_text(f"🗑️ Folder <b>{folder}</b> deleted.", parse_mode="HTML")
        await callback_query.answer()

    # ── delete file ──
    elif data.startswith("delete:"):
        fid = data.split(":", 1)[1]
        try:
            res = await files_collection.delete_one({"_id": ObjectId(fid)})
            if res.deleted_count:
                await callback_query.message.edit_text("🗑️ <b>File deleted.</b>")
            else:
                await callback_query.answer("File not found.", show_alert=True)
        except Exception as e:
            await callback_query.answer("Error deleting file.", show_alert=True)

    # ── rename file ──
    elif data.startswith("rename:"):
        fid = data.split(":", 1)[1]
        await state.set_state(RenameFile.waiting_for_new_name)
        await state.update_data(file_id=fid)
        await callback_query.message.reply("<b>Send the new file name:</b>")
        await callback_query.answer()

    # ── add folder ──
    elif data.startswith("addfolder:"):
        fid = data.split(":", 1)[1]
        await state.set_state(AddFolder.waiting_for_folders)
        await state.update_data(file_id=fid)
        # Show existing folders as quick options
        folders_cursor = folders_collection.find({"user_id": uid}).sort("name", 1)
        existing = [doc["name"] for doc in await folders_cursor.to_list(length=50)]
        kb = []
        for f in existing:
            kb.append([InlineKeyboardButton(text=f"📁 {f}", callback_data=f"quickfolder:{fid}:{f}")])
        kb.append([InlineKeyboardButton(text="✏️ Type custom name", callback_data=f"typefolder:{fid}")])
        if kb:
            await callback_query.message.reply(
                "📁 Pick a folder or type a custom one:",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=kb)
            )
        else:
            await callback_query.message.reply("<b>Send folder name(s) (comma-separated):</b>")
        await callback_query.answer()

    elif data.startswith("quickfolder:"):
        _, fid, folder = data.split(":", 2)
        await _assign_folder(uid, fid, [folder], callback_query.message)
        await state.clear()
        await callback_query.answer()

    elif data.startswith("typefolder:"):
        fid = data.split(":", 1)[1]
        await state.set_state(AddFolder.waiting_for_folders)
        await state.update_data(file_id=fid)
        await callback_query.message.reply("<b>Send folder name(s) (comma-separated):</b>")
        await callback_query.answer()

    # ── convert video note ──
    elif data.startswith("convert_video_note:"):
        await _convert_video_note(callback_query)

    # ── set_parent for createfolder ──
    elif data.startswith("set_parent:"):
        await set_parent_callback(callback_query, state)

    else:
        await callback_query.answer()


async def _assign_folder(uid, file_mongo_id, folder_list, reply_msg):
    await files_collection.update_one(
        {"_id": ObjectId(file_mongo_id)}, {"$addToSet": {"folders": {"$each": folder_list}}}
    )
    for f in folder_list:
        await folders_collection.update_one(
            {"user_id": uid, "name": f, "parent": None},
            {"$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True
        )
    await reply_msg.reply(f"✅ Added to: {', '.join('📁 '+f for f in folder_list)}")


# ── FSM reply handlers ────────────────────────────────────────────────────────

async def rename_file_handler(message: Message, state: FSMContext):
    data = await state.get_data()
    fid  = data.get("file_id")
    await files_collection.update_one({"_id": ObjectId(fid)}, {"$set": {"file_name": message.text}})
    await message.reply(f"✅ Renamed to <b>{message.text}</b>")
    await state.clear()

async def folder_reply_handler(message: Message, state: FSMContext):
    data    = await state.get_data()
    fid     = data.get("file_id")
    folders = [f.strip() for f in message.text.split(",") if f.strip()]
    await _assign_folder(message.from_user.id, fid, folders, message)
    await state.clear()

async def rename_folder_reply_handler(message: Message, state: FSMContext):
    data       = await state.get_data()
    old_folder = data.get("folder")
    new_folder = message.text.strip()
    uid        = message.from_user.id
    await files_collection.update_many(
        {"user_id": uid, "folders": old_folder},
        {"$set": {"folders.$[elem]": new_folder}},
        array_filters=[{"elem": old_folder}]
    )
    await folders_collection.update_one(
        {"user_id": uid, "name": old_folder}, {"$set": {"name": new_folder}}
    )
    await message.reply(f"✅ Folder renamed to <b>{new_folder}</b>")
    await state.clear()


# ── Video note conversion ─────────────────────────────────────────────────────

async def _convert_video_note(callback_query: CallbackQuery):
    fid      = callback_query.data.split(":", 1)[1]
    file_doc = await files_collection.find_one({"_id": ObjectId(fid)})
    if not file_doc:
        await callback_query.answer("File not found.", show_alert=True)
        return
    tg_file_id = file_doc["file_id"]
    msg        = callback_query.message
    kb         = msg.reply_markup

    def bar(p): return f"[{'█'*(p//10)}{'░'*(10-p//10)}] {p}%"

    try:
        await _edit(msg, kb, f"\n\n⏳ Progress:\n{bar(0)}")
        tg_file = await bot.get_file(tg_file_id)
        await _edit(msg, kb, f"\n\n⏳ Progress:\n{bar(20)} (Downloading...)")
        data    = await bot.download_file(tg_file.file_path)
        inp     = f"/tmp/{tg_file_id}.mp4"
        out     = f"/tmp/{tg_file_id}_circle.mp4"
        with open(inp, "wb") as f:
            f.write(data.getvalue())
        await _edit(msg, kb, f"\n\n⏳ Progress:\n{bar(50)} (Processing...)")
        subprocess.run(["ffmpeg","-y","-i",inp,
            "-vf","crop=min(iw\\,ih):min(iw\\,ih),scale=512:512",
            "-c:v","libx264","-preset","fast","-crf","28","-an",out], check=True)
        await _edit(msg, kb, f"\n\n⏳ Progress:\n{bar(80)} (Uploading...)")
        await bot.send_video_note(msg.chat.id, FSInputFile(out, filename="video_note.mp4"), length=512)
        await _edit(msg, kb, f"\n\n✅ Done!\n{bar(100)}")
        await callback_query.answer("Video note sent!")
        for p in (inp, out):
            try: os.remove(p)
            except: pass
    except Exception:
        logging.exception("Video note conversion failed")
        await _edit(msg, kb, "\n\n❌ Failed to convert.")
        await callback_query.answer("Failed.", show_alert=True)

async def _edit(msg, kb, suffix):
    try:
        await bot.edit_message_text(
            text=msg.html_text + suffix,
            chat_id=msg.chat.id, message_id=msg.message_id,
            reply_markup=kb, parse_mode="HTML"
        )
    except Exception:
        pass


# ── Sticker ───────────────────────────────────────────────────────────────────

async def sticker_cmd(message: Message):
    await list_sticker_packs(message, db)

async def handle_sticker(message: Message):
    await add_sticker_to_pack(message, bot, db)


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(level=logging.INFO)

    # Register handlers
    dp.message.register(start_cmd,                  Command("start"))
    dp.message.register(folders_cmd,                Command("folders"))
    dp.message.register(setpassword_cmd,            Command("setpassword"))
    dp.message.register(createfolder_cmd,           Command("createfolder"))
    dp.message.register(sticker_cmd,                Command("sticker"))
    dp.message.register(save_file,
        lambda m: m.document or m.video or m.audio or m.photo or m.voice or m.video_note)
    dp.message.register(setpassword_handler,        SetPassword.waiting_for_password)
    dp.message.register(rename_file_handler,        RenameFile.waiting_for_new_name)
    dp.message.register(folder_reply_handler,       AddFolder.waiting_for_folders)
    dp.message.register(rename_folder_reply_handler,FolderPagination.selecting_folder)
    dp.message.register(createfolder_name_handler,  CreateFolder.waiting_for_folder_name)
    dp.message.register(handle_sticker,             lambda m: m.sticker is not None)
    dp.inline_query.register(inline_query_handler)
    dp.callback_query.register(callback_query_handler)

    await bot.set_my_commands([
        BotCommand(command="start",        description="Start SecureBox"),
        BotCommand(command="folders",      description="Browse folders"),
        BotCommand(command="createfolder", description="Create a new folder"),
        BotCommand(command="setpassword",  description="Set WebUI password"),
        BotCommand(command="sticker",      description="View sticker packs"),
    ])

    # Start Web UI
    from webui import create_app
    from aiohttp import web as aio_web
    app = create_app(
        files_collection=files_collection,
        folders_collection=folders_collection,
        settings_collection=settings_collection,
        bot_instance=bot,
    )
    runner = aio_web.AppRunner(app)
    await runner.setup()
    await aio_web.TCPSite(runner, "0.0.0.0", WEBUI_PORT).start()
    logging.info("WebUI running on port %s", WEBUI_PORT)

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

# NOTE: Pyrogram client is started in main() if credentials are available.
# See pyrogram_client.py for first-time authentication.
