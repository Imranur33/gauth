from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from oauthlib.oauth2 import WebApplicationClient
import requests
import uuid
import os
from dotenv import load_dotenv
from typing import List

load_dotenv()

# Google OAuth configuration
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')

# GitHub OAuth configuration
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI')

SESSION_SECRET_KEY = os.getenv('SESSION_SECRET_KEY')

app = FastAPI()

# Add Session Middleware
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

# Add CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

# Google API endpoints
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

# Github API endpoints
GITHUB_AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"

# Create an OAuth 2.0 client
client = WebApplicationClient(CLIENT_ID)
github_client = WebApplicationClient(GITHUB_CLIENT_ID)

# WebSocket connections storage
websocket_connections: List[WebSocket] = []

@app.get("/")
async def read_root():
    return {"message": "Hello Working"}

@app.get("/auth/google/login")
async def google_login(request: Request):
    state = str(uuid.uuid4())
    request.session["state"] = state

    authorization_url = client.prepare_request_uri(
        AUTHORIZATION_URL,
        redirect_uri=REDIRECT_URI,
        scope=["profile", "email"],
        state=state,
    )

    return RedirectResponse(authorization_url)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    code = request.query_params.get('code')
    state = request.query_params.get('state')

    if not code or not state:
        raise HTTPException(status_code=400, detail="Invalid callback request")

    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        # Exchange authorization code for an access token
        token_url, headers, body = client.prepare_token_request(
            TOKEN_URL,
            authorization_response=str(request.url),  # Ensure URL is a string
            redirect_url=REDIRECT_URI,
            code=code
        )
        token_response = requests.post(token_url, headers=headers, data=body, auth=(CLIENT_ID, CLIENT_SECRET))
        token_response.raise_for_status()
        token_data = client.parse_request_body_response(token_response.text)

        # Get user info
        userinfo_endpoint, headers, _ = client.add_token(USERINFO_URL)
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()

        # Notify WebSocket clients about the login success
        for ws in websocket_connections:
            await ws.send_text(f"User {user_info['email']} logged in successfully")

        return templates.TemplateResponse("profile.html", {"request": request, "user_info": user_info})
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail="Error fetching user info")
    
# GitHub OAuth Routes
@app.get("/auth/github/login")
async def github_login(request: Request):
    state = str(uuid.uuid4())
    request.session["state"] = state

    authorization_url = github_client.prepare_request_uri(
        GITHUB_AUTHORIZATION_URL,
        redirect_uri=GITHUB_REDIRECT_URI,
        state=state,
    )
    return RedirectResponse(authorization_url)

@app.get("/auth/github/callback")
async def github_callback(request: Request):
    code = request.query_params.get('code')
    state = request.query_params.get('state')

    if not code or not state:
        raise HTTPException(status_code=400, detail="Invalid callback request")

    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        # Exchange authorization code for access token
        token_url, headers, body = github_client.prepare_token_request(
            GITHUB_TOKEN_URL,
            authorization_response=str(request.url),
            redirect_url=GITHUB_REDIRECT_URI,
            code=code
        )
        token_response = requests.post(token_url, headers=headers, data=body, auth=(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET))
        token_response.raise_for_status()
        token_data = github_client.parse_request_body_response(token_response.text)

        # Get user info
        userinfo_endpoint, headers, _ = github_client.add_token(GITHUB_USERINFO_URL)
        userinfo_response = requests.get(userinfo_endpoint, headers=headers)
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()

        # Notify WebSocket clients
        for ws in websocket_connections:
            await ws.send_text(f"GitHub User {user_info['login']} logged in successfully")

        return templates.TemplateResponse("profile.html", {"request": request, "user_info": user_info})
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=500, detail="Error fetching user info")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    websocket_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle received messages from WebSocket client
            # Example: Send a confirmation back
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)
        print("WebSocket disconnected")

