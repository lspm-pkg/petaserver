from uuid import UUID
from fastapi import Request
from typing import Optional, cast
from ..models import Folder, User, File
from ..consts import NULL_UUID
import re

async def get_at_path(user: User, path: Optional[str] = None):
    """
    Gets a file or folder at a specific path for a given user.
    """
    if not path or path == "/":
        return await Folder.get(id=user.root_folder)
    else:
        folder = await Folder.get(id=user.root_folder)
        # Clean up leading/trailing slashes for reliable splitting
        clean_path = path.strip('/')
        for seg in clean_path.split("/"):
            if not seg: # Should not happen with strip, but good practice
                continue
            seg_id = folder.files.get(seg)
            if not seg_id:
                raise FileNotFoundError(f"'{seg}' not found in '{folder.name}'")
            
            # Check if it's a file first
            file_query = await File.filter(id=UUID(seg_id)).first()
            if file_query:
                # If this is the last segment, we found the file.
                # If not, it's an error (path continues through a file).
                # The logic implicitly handles this by the loop ending or continuing.
                return file_query

            folder_query = await Folder.filter(id=UUID(seg_id)).first()
            if not folder_query:
                raise FileNotFoundError(f"Path component '{seg}' with ID '{seg_id}' is orphaned.")
            folder = folder_query
        
        return folder

async def get_parent(object: Folder | File) -> Folder:
    parent_id = object.parent
    if parent_id == NULL_UUID:
        raise AssertionError("Cannot get parent of root directory")
    parent = await Folder.get_or_none(id=parent_id)
    if not parent:
        raise AssertionError(f"Orphaned object found with non-null parent ID {parent_id}")
    return parent

async def get_folder_with_id(id: str | UUID) -> Folder:
    if isinstance(id, str):
        id = UUID(id)
    folder_query = await Folder.get_or_none(id=id)
    if not folder_query:
        raise FileNotFoundError
    return folder_query

async def get_file_with_id(id: str | UUID) -> File:
    if isinstance(id, str):
        id = UUID(id)
    file_query = await File.get_or_none(id=id)
    if not file_query:
        raise FileNotFoundError
    return file_query

def validate_email(email: str) -> bool:
    return bool(re.compile(r"[^@]+@[^@]+\.[^@]+").match(email))
