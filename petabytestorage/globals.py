from uuid import UUID
import logging

AUTHTOKENS: dict[str, UUID] = {} # TODO: Set up Valkey/Redis instead of this shit
CACHE: dict[int, bytes] = {}

logger = logging.getLogger("uvicorn")