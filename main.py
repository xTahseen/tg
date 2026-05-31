import logging
import os
import subprocess
import asyncio
import math
from datetime import datetime
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import (
    Message,
    InlineQuery,
    InlineQueryResultArticle,
    InlineQueryResultCachedAudio,
    InlineQueryResultCachedDocument,
    InlineQueryResultCachedGif,
    InlineQueryResultCachedMpeg4Gif,
    InlineQueryResultCachedPhoto,
    InlineQueryResultCachedSticker,
    InlineQueryResultCachedVideo,
    InlineQueryResultCachedVoice,
    CallbackQuery,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    InputTextMessageContent,
    BotCommand,
    FSInputFile,
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

BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGO_URI = os.getenv("MONGO_URI")
STORAGE_CHANNEL_ID = os.getenv("STORAGE_CHANNEL_ID")
WEBUI_PASSWORD = os.getenv("WEBUI_PASSWORD", "")
WEBUI_SECRET_KEY = os.getenv("WEBUI_SECRET_KEY", "securebox-secret-key-change-me")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

mongo_client = AsyncIOMotorClient(MONGO_URI)
db = mongo_client["file_store_bot"]
files_collection = db["files"]
folders_collection = db["folders"]   # renamed from tags_collection


class RenameFile(StatesGroup):
    waiting_for_new_name = State()


class AddFolder(StatesGroup):           # renamed from AddTag
    waiting_for_folders = State()


class FolderPagination(StatesGroup):    # renamed from TagPagination
    selecting_folder = State()


def format_file_size(size_in_bytes):
    if size_in_bytes is None:
        return "Unknown"
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 ** 2:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 ** 3:
        return f"{size_in_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_in_bytes / 1024 ** 3:.2f} GB"


async def start_cmd(message: Message):
    markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Explore", switch_inline_query_current_chat="")]
        ]
    )
    await message.answer(
        "Send me any file (doc, video, image, etc.) and I'll store it.\n",
        parse_mode="HTML",
        reply_markup=markup
    )


async def folders_cmd(message: Message, state: FSMContext):
    user_id = message.from_user.id
    folders_cursor = folders_collection.find({"user_id": user_id}).sort("created_at", -1)
    folders = [doc["folder"] for doc in await folders_cursor.to_list(length=1000)]
    if not folders:
        await message.answer("You don't have any folders yet.")
        return
    await send_folder_page(message, folders, 0, state)


async def send_folder_page(message_or_cb, folders, page, state):
    FOLDERS_PER_PAGE = 10
    COLS = 2
    total_folders = len(folders)
    start = page * FOLDERS_PER_PAGE
    end = start + FOLDERS_PER_PAGE
    page_folders = folders[start:end]

    keyboard = []
    for i in range(0, len(page_folders), COLS):
        row = []
        for folder in page_folders[i:i+COLS]:
            row.append(InlineKeyboardButton(text=f"📁 {folder}", callback_data=f"folder_menu:{folder}"))
        keyboard.append(row)

    nav_buttons = []
    max_page = math.ceil(total_folders / FOLDERS_PER_PAGE) - 1
    if page > 0:
        nav_buttons.append(
            InlineKeyboardButton(text="⬅️ Prev", callback_data=f"folders_page:{page-1}")
        )
    if page < max_page:
        nav_buttons.append(
            InlineKeyboardButton(text="Next ➡️", callback_data=f"folders_page:{page+1}")
        )
    if nav_buttons:
        keyboard.append(nav_buttons)

    markup = InlineKeyboardMarkup(inline_keyboard=keyboard)
    text = f"📁 Your Folders (Page {page+1}/{max_page+1} | Total: {total_folders}):"

    if isinstance(message_or_cb, Message):
        await message_or_cb.answer(text, reply_markup=markup)
    elif isinstance(message_or_cb, CallbackQuery):
        if message_or_cb.message:
            await message_or_cb.message.edit_text(text, reply_markup=markup)
        await message_or_cb.answer()


async def forward_to_storage_channel(message: Message):
    try:
        forwarded_msg = await message.forward(STORAGE_CHANNEL_ID)
        return forwarded_msg.message_id
    except Exception as e:
        logging.error(f"Error forwarding message to storage channel: {e}")
        return None


async def save_file(message: Message):
    file_id = None
    file_name = "Unnamed"
    file_size = None
    file_type = None
    message_date = message.date.strftime("%Y-%m-%d %H:%M:%S")

    if message.document:
        file_id = message.document.file_id
        file_name = message.document.file_name
        file_size = message.document.file_size
        file_type = "document"
    elif message.video:
        file_id = message.video.file_id
        file_name = "video.mp4"
        file_size = message.video.file_size
        file_type = "video"
    elif message.audio:
        file_id = message.audio.file_id
        file_name = message.audio.file_name or "audio.mp3"
        file_size = message.audio.file_size
        file_type = "audio"
    elif message.photo:
        file_id = message.photo[-1].file_id
        file_name = "photo.jpg"
        file_size = message.photo[-1].file_size
        file_type = "photo"
    elif message.voice:
        file_id = message.voice.file_id
        file_name = "voice.ogg"
        file_size = message.voice.file_size
        file_type = "voice"
    elif message.video_note:
        file_id = message.video_note.file_id
        file_name = "video_note.mp4"
        file_size = message.video_note.file_size
        file_type = "video_note"

    if file_id:
        existing_file = await files_collection.find_one({"file_id": file_id, "user_id": message.from_user.id})
        if existing_file:
            mongo_id = str(existing_file["_id"])
            buttons = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="✏️ Rename", callback_data=f"rename:{mongo_id}")],
                [InlineKeyboardButton(text="🗑️ Delete", callback_data=f"delete:{mongo_id}")],
                [InlineKeyboardButton(text="📁 Add to Folder", callback_data=f"addfolder:{mongo_id}")]
            ])
            if existing_file.get("file_type") == "video":
                buttons.inline_keyboard.append(
                    [InlineKeyboardButton(text="🔄 Convert to Video Note", callback_data=f"convert_video_note:{mongo_id}")]
                )
            await message.reply(
                "<b>This file is already saved in your storage.</b>\n"
                f"<b>File Name:</b> {existing_file['file_name']}\n"
                f"<b>File Type:</b> {existing_file['file_type']}\n"
                f"<b>File Size:</b> {format_file_size(existing_file.get('file_size', 0))}\n"
                f"<b>Message Date:</b> {message_date}",
                reply_markup=buttons,
                parse_mode="HTML"
            )
        else:
            storage_message_id = await forward_to_storage_channel(message)
            result = await files_collection.insert_one({
                "user_id": message.from_user.id,
                "file_id": file_id,
                "file_name": file_name,
                "file_size": file_size,
                "file_type": file_type,
                "folders": [],      # renamed from "tags"
                "message_date": message.date,
                "storage_message_id": storage_message_id
            })
            mongo_id = str(result.inserted_id)
            buttons = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="✏️ Rename", callback_data=f"rename:{mongo_id}")],
                [InlineKeyboardButton(text="🗑️ Delete", callback_data=f"delete:{mongo_id}")],
                [InlineKeyboardButton(text="📁 Add to Folder", callback_data=f"addfolder:{mongo_id}")]
            ])
            if file_type == "video":
                buttons.inline_keyboard.append(
                    [InlineKeyboardButton(text="🔄 Convert to Video Note", callback_data=f"convert_video_note:{mongo_id}")]
                )
            await message.reply(
                "<b>File saved successfully! 🎉</b>\n"
                f"<b>File Name:</b> {file_name}\n"
                f"<b>File Type:</b> {file_type}\n"
                f"<b>File Size:</b> {format_file_size(file_size)}\n"
                f"<b>Message Date:</b> {message_date}",
                reply_markup=buttons,
                parse_mode="HTML"
            )


async def inline_query_handler(inline_query: InlineQuery):
    user_id = inline_query.from_user.id
    query = inline_query.query.lower()
    files_cursor = files_collection.find({"user_id": user_id})
    files = await files_cursor.to_list(length=50)

    results = []
    for f in files:
        file_size_str = format_file_size(f.get("file_size", 0))
        message_date = f.get("message_date")
        folders = f.get("folders", [])
        folders_str = ", ".join(folders) if folders else "No folders"

        if message_date:
            if isinstance(message_date, datetime):
                message_date_str = message_date.strftime("%Y-%m-%d %H:%M:%S")
            else:
                message_date_str = str(message_date)
        else:
            message_date_str = "Unknown"

        if query in f["file_name"].lower() or any(query in folder.lower() for folder in folders):
            file_type = f.get("file_type")
            file_id = f.get("file_id")
            title = f.get("file_name")
            description = (
                f"{file_type.capitalize()} | "
                f"{file_size_str} | "
                f"{message_date_str} | "
                f"{folders_str}"
            )

            try:
                if file_type == "photo":
                    results.append(
                        InlineQueryResultCachedPhoto(
                            id=str(f["_id"]),
                            title=title,
                            photo_file_id=file_id,
                            description=description
                        )
                    )
                elif file_type == "video":
                    results.append(
                        InlineQueryResultCachedVideo(
                            id=str(f["_id"]),
                            title=title,
                            video_file_id=file_id,
                            description=description
                        )
                    )
                elif file_type == "audio":
                    results.append(
                        InlineQueryResultCachedAudio(
                            id=str(f["_id"]),
                            title=title,
                            audio_file_id=file_id
                        )
                    )
                elif file_type == "voice":
                    results.append(
                        InlineQueryResultCachedVoice(
                            id=str(f["_id"]),
                            title=title,
                            voice_file_id=file_id
                        )
                    )
                elif file_type == "sticker":
                    results.append(
                        InlineQueryResultCachedSticker(
                            id=str(f["_id"]),
                            sticker_file_id=file_id
                        )
                    )
                elif file_type == "document" or file_type == "video_note":
                    results.append(
                        InlineQueryResultCachedDocument(
                            id=str(f["_id"]),
                            title=title,
                            document_file_id=file_id,
                            description=description
                        )
                    )
                else:
                    results.append(
                        InlineQueryResultArticle(
                            id=str(f["_id"]),
                            title=title,
                            input_message_content=InputTextMessageContent(
                                message_text=title
                            ),
                            description=description
                        )
                    )
            except Exception as e:
                results.append(
                    InlineQueryResultArticle(
                        id=str(f["_id"]),
                        title=title,
                        input_message_content=InputTextMessageContent(
                            message_text=f"[Error sending file]\n\n{title}"
                        ),
                        description=description
                    )
                )

    await bot.answer_inline_query(inline_query.id, results=results, cache_time=0)


async def callback_query_handler(callback_query: CallbackQuery, state: FSMContext):
    data = callback_query.data
    user_id = callback_query.from_user.id

    if data.startswith("delete:"):
        file_id = data.split(":", 1)[1]
        try:
            object_id = ObjectId(file_id)
            result = await files_collection.delete_one({"_id": object_id})
            if result.deleted_count > 0:
                if callback_query.message:
                    await callback_query.message.edit_text("<b>The file has been deleted successfully.</b>", parse_mode="HTML")
                else:
                    await callback_query.answer("The file has been deleted successfully.", show_alert=True)
            else:
                await callback_query.answer("Failed to delete the file. It may no longer exist.", show_alert=True)
        except Exception as e:
            await callback_query.answer("An error occurred while deleting the file.", show_alert=True)
            logging.error(f"Error deleting file: {e}")

    elif data.startswith("rename:"):
        file_id = data.split(":", 1)[1]
        await state.set_state(RenameFile.waiting_for_new_name)
        await state.update_data(file_id=file_id)
        try:
            await callback_query.message.reply("<b>Please send the new name for the file:</b>", parse_mode="HTML")
        except:
            pass
        await callback_query.answer("Please send the new name in this chat.", show_alert=True)

    elif data.startswith("addfolder:"):
        file_id = data.split(":", 1)[1]
        await state.set_state(AddFolder.waiting_for_folders)
        await state.update_data(file_id=file_id)
        try:
            await callback_query.message.reply("<b>Please send the folder name(s) for the file (comma-separated for multiple folders):</b>", parse_mode="HTML")
        except:
            pass
        await callback_query.answer("Please send the folder name(s) in this chat.", show_alert=True)

    elif data.startswith("folders_page:"):
        page = int(data.split(":", 1)[1])
        folders_cursor = folders_collection.find({"user_id": user_id}).sort("created_at", -1)
        folders = [doc["folder"] for doc in await folders_cursor.to_list(length=1000)]
        await send_folder_page(callback_query, folders, page, state)

    elif data.startswith("folder_menu:"):
        folder = data.split(":", 1)[1]
        keyboard = [
            [InlineKeyboardButton(text="🔎 Inline Search", switch_inline_query_current_chat=folder)],
            [InlineKeyboardButton(text="✏️ Rename Folder", callback_data=f"rename_folder_menu:{folder}")],
            [InlineKeyboardButton(text="🗑️ Delete Folder", callback_data=f"delete_folder_menu:{folder}")]
        ]
        markup = InlineKeyboardMarkup(inline_keyboard=keyboard)
        await callback_query.message.edit_text(
            f"📁 Folder: <b>{folder}</b>\n\nChoose an action:",
            reply_markup=markup,
            parse_mode="HTML"
        )
        await callback_query.answer()

    elif data.startswith("rename_folder_menu:"):
        folder = data.split(":", 1)[1]
        await state.set_state(FolderPagination.selecting_folder)
        await state.update_data(folder=folder)
        await callback_query.message.reply(f"<b>Send the new name for the folder</b> <b>{folder}</b>:", parse_mode="HTML")
        await callback_query.answer()

    elif data.startswith("delete_folder_menu:"):
        folder = data.split(":", 1)[1]
        await files_collection.update_many(
            {"user_id": user_id, "folders": folder},
            {"$pull": {"folders": folder}}
        )
        await folders_collection.delete_one({"user_id": user_id, "folder": folder})
        await callback_query.message.edit_text(f"<b>📁 Folder '{folder}' has been deleted.</b>", parse_mode="HTML")
        await callback_query.answer()

    elif data.startswith("convert_video_note:"):
        file_id = data.split(":", 1)[1]
        file_doc = await files_collection.find_one({"_id": ObjectId(file_id)})
        if not file_doc:
            await callback_query.answer("File not found.", show_alert=True)
            return
        tg_file_id = file_doc.get("file_id")
        message = callback_query.message
        keyboard = message.reply_markup

        def make_bar(pct):
            bars = int(pct // 10)
            return f"[{'█'*bars}{'░'*(10-bars)}] {pct}%"

        try:
            await bot.edit_message_text(
                text=message.html_text + f"\n\n⏳ <b>Progress</b>:\n{make_bar(0)}",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            telegram_file = await bot.get_file(tg_file_id)
            await bot.edit_message_text(
                text=message.html_text + f"\n\n⏳ <b>Progress</b>:\n{make_bar(20)} (Downloading...)",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            file_path = telegram_file.file_path
            file_bytes = await bot.download_file(file_path)
            input_path = f"/tmp/{tg_file_id}.mp4"
            output_path = f"/tmp/{tg_file_id}_circle.mp4"
            with open(input_path, "wb") as f:
                f.write(file_bytes.getvalue())
            await bot.edit_message_text(
                text=message.html_text + f"\n\n⏳ <b>Progress</b>:\n{make_bar(50)} (Processing...)",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            ffmpeg_cmd = [
                "ffmpeg", "-y",
                "-i", input_path,
                "-vf", "crop=min(iw\\,ih):min(iw\\,ih),scale=512:512",
                "-c:v", "libx264", "-preset", "fast", "-crf", "28",
                "-an", output_path
            ]
            subprocess.run(ffmpeg_cmd, check=True)
            await bot.edit_message_text(
                text=message.html_text + f"\n\n⏳ <b>Progress</b>:\n{make_bar(80)} (Uploading...)",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            await bot.send_video_note(
                chat_id=message.chat.id,
                video_note=FSInputFile(output_path, filename="video_note.mp4"),
                length=512
            )
            await bot.edit_message_text(
                text=message.html_text + f"\n\n✅ <b>Done!</b> Your circle video note is ready.\n{make_bar(100)}",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            await callback_query.answer("Video note sent!", show_alert=True)
            try:
                os.remove(input_path)
                os.remove(output_path)
            except Exception:
                pass
        except Exception as e:
            logging.exception("Failed to send video note")
            await bot.edit_message_text(
                text=message.html_text + "\n\n❌ <b>Failed to convert or send video note.</b>",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=keyboard,
                parse_mode="HTML"
            )
            await callback_query.answer("Failed to convert or send video note.", show_alert=True)


async def rename_file_handler(message: Message, state: FSMContext):
    data = await state.get_data()
    file_id = data.get("file_id")
    if not file_id:
        await message.reply("<b>Something went wrong. Try again.</b>", parse_mode="HTML")
        return

    new_name = message.text
    object_id = ObjectId(file_id)
    await files_collection.update_one({"_id": object_id}, {"$set": {"file_name": new_name}})
    await message.reply(f"<b>File renamed to:</b> {new_name}", parse_mode="HTML")
    await state.clear()


async def folder_reply_handler(message: Message, state: FSMContext):
    data = await state.get_data()
    file_id = data.get("file_id")
    if not file_id:
        await message.reply("<b>Something went wrong. Try again.</b>", parse_mode="HTML")
        return

    folders = [folder.strip() for folder in message.text.split(",")]
    object_id = ObjectId(file_id)
    await files_collection.update_one({"_id": object_id}, {"$set": {"folders": folders}})
    for folder in folders:
        await folders_collection.update_one(
            {"user_id": message.from_user.id, "folder": folder},
            {"$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True
        )
    await message.reply(f"<b>📁 Added to folders:</b> {', '.join(folders)}", parse_mode="HTML")
    await state.clear()


async def rename_folder_reply_handler(message: Message, state: FSMContext):
    data = await state.get_data()
    old_folder = data.get("folder")
    user_id = message.from_user.id
    new_folder = message.text.strip()
    if not old_folder or not new_folder:
        await message.reply("<b>Something went wrong. Try again.</b>", parse_mode="HTML")
        return
    await files_collection.update_many(
        {"user_id": user_id, "folders": old_folder},
        {"$set": {"folders.$[elem]": new_folder}},
        array_filters=[{"elem": old_folder}]
    )
    folder_doc = await folders_collection.find_one({"user_id": user_id, "folder": old_folder})
    if folder_doc:
        created_at = folder_doc.get("created_at", datetime.utcnow())
        await folders_collection.delete_one({"user_id": user_id, "folder": old_folder})
        await folders_collection.update_one(
            {"user_id": user_id, "folder": new_folder},
            {"$setOnInsert": {"created_at": created_at}},
            upsert=True
        )
    await message.reply(f"<b>📁 Folder</b> <b>{old_folder}</b> <b>renamed to</b> <b>{new_folder}</b>.", parse_mode="HTML")
    await state.clear()


async def sticker_cmd(message: Message):
    await list_sticker_packs(message, db)


async def handle_sticker(message: Message):
    await add_sticker_to_pack(message, bot, db)


async def main():
    logging.basicConfig(level=logging.INFO)
    dp.message.register(start_cmd, Command(commands=["start"]))
    dp.message.register(folders_cmd, Command(commands=["folders"]))
    dp.message.register(sticker_cmd, Command(commands=["sticker"]))
    dp.message.register(save_file, lambda msg: msg.document or msg.video or msg.audio or msg.photo or msg.voice or msg.video_note)
    dp.message.register(rename_file_handler, RenameFile.waiting_for_new_name)
    dp.message.register(folder_reply_handler, AddFolder.waiting_for_folders)
    dp.message.register(rename_folder_reply_handler, FolderPagination.selecting_folder)
    dp.message.register(handle_sticker, lambda message: message.sticker is not None)
    dp.inline_query.register(inline_query_handler)
    dp.callback_query.register(callback_query_handler)

    await bot.set_my_commands([
        BotCommand(command="start", description="Start interacting with the bot"),
        BotCommand(command="folders", description="Browse your folders"),
        BotCommand(command="sticker", description="View your sticker packs"),
    ])

    # Start the web UI alongside polling
    from webui import create_app
    from aiohttp import web as aio_web
    app = create_app(
        files_collection=files_collection,
        folders_collection=folders_collection,
        bot_instance=bot
    )
    runner = aio_web.AppRunner(app)
    await runner.setup()
    site = aio_web.TCPSite(runner, "0.0.0.0", int(os.getenv("WEBUI_PORT", 8080)))
    await site.start()
    logging.info("Web UI started on port %s", os.getenv("WEBUI_PORT", 8080))

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
