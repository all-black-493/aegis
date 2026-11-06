from fastapi import APIRouter, Depends

from aegis.apps.api.auth import require_actor
from aegis.apps.api.v1.endpoints import me, tasks

# Every /v1 route needs a token, here rather than on each endpoint, so that none can forget it.
router = APIRouter(prefix="/v1", dependencies=[Depends(require_actor)])
router.include_router(me.router)
router.include_router(tasks.router)
