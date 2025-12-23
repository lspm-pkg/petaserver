# __main__.py
from uuid import UUID
import json
import asyncio
import io
from fastapi import APIRouter, FastAPI, Request, UploadFile, Form, Depends, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse, JSONResponse
from uvicorn import Config, Server
from starlette.middleware.sessions import SessionMiddleware
from typing import Any
from tortoise import Tortoise
from .models import Folder, File, User
from .api_models import Signup, Login
from .globals import logger, AUTHTOKENS
from .utils import get_at_path
from .consts import NULL_UUID
from .bot import UploadBot
from . import config
import os
import bcrypt
import secrets

bot = UploadBot(config.Upload.Discord.UPLOAD_CHANNEL_ID, config.Upload.Discord.TOKEN, config.Upload.CHUNK_SIZE)
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET)
api_router = APIRouter(prefix="/api")

async def get_current_user(request: Request) -> User:
    token = request.session.get("token")
    if not token or not (user_id := AUTHTOKENS.get(token)):
        raise HTTPException(status_code=401, detail="Authentication failed")
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@api_router.post("/fs/write")
async def fs_write(user: User = Depends(get_current_user), path: str = Form(...), start: int = Form(...), data: UploadFile = ...):
    file = await get_at_path(user, path)
    content = await data.read()
    await bot.discord_patch(file, start, content)
    return {"status": "ok", "written": len(content)}

@api_router.get("/fs/read")
async def fs_read(path: str, size: int, offset: int, user: User = Depends(get_current_user)):
    file = await get_at_path(user, path)
    data = await bot.discord_ranged_download(file, [offset, offset + size - 1])
    return StreamingResponse(io.BytesIO(data), media_type="application/octet-stream")

@api_router.post("/fs/flush")
async def fs_flush(path: str = Form(...), user: User = Depends(get_current_user)):
    await bot.wait_for_uploads()
    return {"status": "ok"}

@api_router.post("/fs/discard")
async def fs_discard(path: str = Form(...), size: int = Form(...), offset: int = Form(...), user: User = Depends(get_current_user)):
    file = await get_at_path(user, path)
    await bot.discord_discard(file, size, offset)
    return {"status": "ok"}

@api_router.post("/fs/truncate")
async def fs_truncate(path: str = Form(...), length: int = Form(...), user: User = Depends(get_current_user)):
    file = await get_at_path(user, path)
    file.size = length
    await file.save(update_fields=['size', 'updated_at'])
    return {"status": "ok"}

@api_router.post("/fs/create")
async def fs_create(path: str = Form(...), user: User = Depends(get_current_user)):
    try:
        await get_at_path(user, path)
    except FileNotFoundError:
        parent_path, name = os.path.split(path)
        parent = await get_at_path(user, parent_path)
        new_file = File(name=name, parent=parent.id, size=0, chunks={})
        await new_file.save()
        parent.files[name] = str(new_file.id)
        await parent.save(update_fields=['files'])
    return {"status": "ok"}

@api_router.post("/register", tags=["Authentication"])
async def register(signup: Signup):
    if not config.Auth.REGISTRATION_ENABLED: return PlainTextResponse("Registration is disabled.", 403)
    if not (signup.email and signup.password and signup.terms_accepted): return PlainTextResponse("Missing required fields.", 400)
    from .utils import validate_email
    if not validate_email(signup.email): return PlainTextResponse("Email must be a valid email.", 400)
    if await User.filter(email=signup.email).exists(): return PlainTextResponse("User already exists", 400)
    
    salt = bcrypt.gensalt()
    root_folder = await Folder.create(name="root", files={}, parent=NULL_UUID)
    await User.create(email=signup.email, password=bcrypt.hashpw(signup.password.encode("utf-8"), salt), salt=salt, root_folder=root_folder.id, api_keys=[])
    
    if config.Auth.ONE_ACCOUNT_MODE:
        user_count = await User.all().count()
        if user_count >= 1:
            logger.info("One Account Mode: First user registered. Sealing the blast doors. Disabling all future registrations.")
            config.Auth.REGISTRATION_ENABLED = False
            
    return PlainTextResponse("Account created successfully!", 200)

@api_router.post("/login", tags=["Authentication"])
async def login(request: Request, login: Login):
    user = await User.filter(email=login.email).first()
    if not user or not bcrypt.hashpw(login.password.encode('utf-8'), user.salt) == user.password:
        return JSONResponse({"error": "Invalid username or password!"}, status_code=403)
    token = secrets.token_hex(32)
    AUTHTOKENS[token] = user.id
    request.session["token"] = token
    return JSONResponse({"token": token}, status_code=200)

app.include_router(api_router)

async def main():
    try:
        await Tortoise.init(db_url='sqlite://db.sqlite3', modules={'models': ['petabytestorage.models']})
        await Tortoise.generate_schemas()
        conf = Config(app=app, host=config.Network.HOST, port=config.Network.PORT, timeout_keep_alive=120)
        server = Server(conf)
        bot_task = asyncio.create_task(bot.start())
        server_task = asyncio.create_task(server.serve())
        await asyncio.gather(bot_task, server_task)
    except Exception as e:
        logger.error(f"Main application error: {e}", exc_info=True)
    finally:
        if bot.bot.is_ready():
            await bot.close()
        await Tortoise.close_connections()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down.")
