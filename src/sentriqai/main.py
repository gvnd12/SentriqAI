from fastapi import FastAPI
from sentriqai.core.config import settings

app=FastAPI(title=settings.app_name, debug=settings.debug)

@app.get("/health", tags=["Health"])
async def health_check():
    return{
        "status":"Healthy",
        "application":settings.app_name,
        "environment":settings.environment
    }