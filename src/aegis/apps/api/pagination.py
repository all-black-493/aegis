import base64
import re
from datetime import datetime
from uuid import UUID

from aegis.apps.api.problems import ApiError
from aegis.tasks.repository import Position

DEFAULT_PAGE_SIZE = 50
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,128}")


def encode_cursor(position: Position) -> str:
    raw = f"{position.created_at.isoformat()}|{position.task_id}".encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str) -> Position:
    try:
        if not _CURSOR.fullmatch(cursor):
            raise ValueError("malformed cursor")
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
        created_at, _, task_id = raw.partition("|")
        position = Position(datetime.fromisoformat(created_at), UUID(task_id))
    except ValueError:
        raise ApiError(400, "invalid_cursor") from None
    if position.created_at.tzinfo is None:
        raise ApiError(400, "invalid_cursor")
    return position
