"""Start the local API. The Vite frontend proxies /api to this server."""
import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host=os.environ.get("BACKEND_HOST", "127.0.0.1"),
                port=int(os.environ.get("BACKEND_PORT", "8000")))
