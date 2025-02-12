from fastapi import Request
from typing import List
import time
import logging
import uuid

logger = logging.getLogger(__name__)

class UserContextMiddleware:
    def __init__(self, app, exclude_paths: List[str] = None):
        self.app = app
        self.exclude_paths = exclude_paths or []
        print("[DEBUG] UserContextMiddleware initialized")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        request = Request(scope, receive)
        
        start_time = time.time()
        print(f"[DEBUG] Processing request in UserContextMiddleware: {request.url.path}")
        
        # Skip excluded paths
        if request.url.path in self.exclude_paths:
            print(f"[DEBUG] Path {request.url.path} is excluded")
            return await self.app(scope, receive, send)

        # Initialize state attributes with defaults if they don't exist
        if not hasattr(request.state, "request_id"):
            request.state.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
            print(f"[DEBUG] Set request_id: {request.state.request_id}")

        if not hasattr(request.state, "request_timestamp"):
            request.state.request_timestamp = start_time
            print(f"[DEBUG] Set timestamp: {request.state.request_timestamp}")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                headers[b"X-Process-Time"] = str(time.time() - start_time).encode()
                headers[b"X-Request-ID"] = str(request.state.request_id).encode()
                message["headers"] = [(k, v) for k, v in headers.items()]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            print(f"[DEBUG] Error in UserContextMiddleware: {str(e)}")
            raise