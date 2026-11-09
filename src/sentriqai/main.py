from fastapi import FastAPI

from sentriqai.api.routes.auth import auth_router
from sentriqai.core.config import settings

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.include_router(router=auth_router, prefix="/auth", tags=["Authentication"])

@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "Healthy",
        "application": settings.app_name,
        "environment": settings.environment,
    }
