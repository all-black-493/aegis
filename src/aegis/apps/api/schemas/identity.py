from uuid import UUID

from pydantic import BaseModel


class Me(BaseModel):
    identity_id: UUID
    name: str
    kind: str
    roles: list[str]
    credential_id: UUID | None
