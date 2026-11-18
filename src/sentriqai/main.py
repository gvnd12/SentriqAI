from fastapi import FastAPI

from sentriqai.api.routes.auth import auth_router
from sentriqai.api.routes.log_source import log_source_router
from sentriqai.api.routes.security_event import security_event_router
from sentriqai.api.routes.tenant import tenant_router
from sentriqai.core.config import settings

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.include_router(router=auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(router=tenant_router, prefix="/tenants", tags=["Tenants"])
app.include_router(
    router=log_source_router, prefix="/log-sources", tags=["Log Sources"]
)
app.include_router(
    router=security_event_router, prefix="/log-sources", tags=["Security Events"]
)


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "Healthy",
        "application": settings.app_name,
        "environment": settings.environment,
    }
