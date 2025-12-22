from tortoise.fields.base import Field
from tortoise.models import Model
from tortoise import fields
from typing import Any
from uuid import UUID

class File(Model):
    id = fields.UUIDField(primary_key=True)
    creation_date = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    name = fields.TextField()
    parent = fields.UUIDField()
    size = fields.BigIntField()

    chunks: Field[dict[str, Any]] = fields.JSONField(default=dict)

class Folder(Model):
    id: Field[UUID] = fields.UUIDField(primary_key=True)
    creation_date = fields.DatetimeField(auto_now_add=True)

    name = fields.TextField()
    parent = fields.UUIDField()

    files: Field[dict[str, str]] = fields.JSONField()

class User(Model):
    id: Field[UUID] = fields.UUIDField(primary_key=True)
    email = fields.CharField(max_length=255)

    password = fields.BinaryField()
    salt = fields.BinaryField()

    root_folder = fields.UUIDField()

    api_keys: Field[list[str]] = fields.JSONField(default=list)
