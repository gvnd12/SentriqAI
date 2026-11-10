from fastapi import FastAPI

from sentriqai.api.routes.auth import auth_router
from sentriqai.api.routes.tenant import tenant_router
from sentriqai.core.config import settings

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.include_router(router=auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(router=tenant_router, prefix="/tenants", tags=["Tenants"])


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "Healthy",
        "application": settings.app_name,
        "environment": settings.environment,
    }
