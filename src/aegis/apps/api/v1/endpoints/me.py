from fastapi import APIRouter, Request
from sqlalchemy import select

from aegis.apps.api.context import api_context
from aegis.apps.api.deps import Actor
from aegis.apps.api.schemas.identity import Me
from aegis.identity.schema import identities

router = APIRouter()


@router.get("/me")
def me(request: Request, actor: Actor) -> Me:
    with api_context(request).engine.connect() as connection:
        name = connection.execute(
            select(identities.c.name).where(identities.c.id == actor.identity_id)
        ).scalar_one()
    return Me(
        identity_id=actor.identity_id,
        name=name,
        kind=actor.kind.value,
        roles=sorted(role.value for role in actor.roles),
        credential_id=actor.credential_id,
    )
