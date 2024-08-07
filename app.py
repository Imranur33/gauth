from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException,status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from oauthlib.oauth2 import WebApplicationClient
import requests
import uuid
import os
from dotenv import load_dotenv
from typing import List
import auth
from database import get_db
import database
from models import User
from requests import Session
from auth import create_access_token, get_current_user
import models
import schemas

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
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"

# Create an OAuth 2.0 client
client = WebApplicationClient(CLIENT_ID)
github_client = WebApplicationClient(GITHUB_CLIENT_ID)

# WebSocket connections storage
websocket_connections: List[WebSocket] = []

@app.get("/")
async def read_root():
    return {"message": "Hello Working"}


#google oauth
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
async def google_callback(request: Request,db: Session = Depends(get_db)):
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
        print(user_info)
        # Notify WebSocket clients about the login success
        for ws in websocket_connections:
            await ws.send_text(f"User {user_info['email']} logged in successfully")
        
        

        #  Check if the user exists in your database
        existing_user = db.query(User).filter(User.email == user_info['email']).first()

        # Create a new user if they don't exist
        if not existing_user:
            new_user = User(
                first_name=user_info.get('given_name', ''), 
                last_name=user_info.get('family_name', ''),
                email=user_info['email'],
                password_hash=auth.hash_password("dummy_password")  
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

        #  Generate a JWT token (use existing_user or new_user)
        user_to_encode = existing_user if existing_user else new_user
        access_token = create_access_token(data={"user_id": user_to_encode.id})

        return {"access_token": access_token, "token_type": "bearer","user":user_to_encode}

        #return templates.TemplateResponse("profile.html", {"request": request, "user_info": user_info})
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail="Error fetching user info")
    


@app.get("/auth/github/login")
async def github_login(request: Request):
    state = str(uuid.uuid4())
    request.session["state"] = state

    authorization_url = github_client.prepare_request_uri(
        GITHUB_AUTHORIZATION_URL,
        redirect_uri=GITHUB_REDIRECT_URI,
        scope=["user:email"],
        state=state,
    )
    return RedirectResponse(authorization_url)

@app.get("/auth/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get('code')
    state = request.query_params.get('state')

    if not code or not state:
        raise HTTPException(status_code=400, detail="Invalid callback request")

    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="Invalid state")

    try:
        # 1. Exchange authorization code for access token
        token_url, headers, body = github_client.prepare_token_request(
            GITHUB_TOKEN_URL,
            authorization_response=str(request.url),
            redirect_url=GITHUB_REDIRECT_URI,
            code=code
        )
        token_response = requests.post(
            token_url, headers=headers, data=body, auth=(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
        )
        token_response.raise_for_status()
        token_data = github_client.parse_request_body_response(token_response.text)
        access_token = token_data.get("access_token")

        # 2. Get user info and primary email
        headers = {"Authorization": f"token {access_token}"}
        userinfo_response = requests.get(GITHUB_USERINFO_URL, headers=headers)
        userinfo_response.raise_for_status()
        user_info = userinfo_response.json()

        emails_response = requests.get(GITHUB_EMAILS_URL, headers=headers)
        emails_response.raise_for_status()
        emails_data = emails_response.json()
        primary_email = next(
            (email['email'] for email in emails_data if email['primary']), None
        )

        # 3. Check if user exists; create if not
        existing_user = db.query(User).filter(User.email == primary_email).first()

        if not existing_user:
            new_user = User(
                first_name=user_info.get('login', '').split()[0],
                last_name=user_info.get('login', '').split()[-1],
                email=primary_email,
                password_hash=auth.hash_password("dummy_password")  # Use auth.hash_password
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            user_to_encode = new_user
        else:
            user_to_encode = existing_user

        # 4. Generate a JWT token
        access_token = auth.create_access_token(data={"user_id": user_to_encode.id})  # Use auth.create_access_token
        return {"access_token": access_token, "token_type": "bearer", "user": user_to_encode}

    # except IntegrityError as e:
    #     db.rollback()  # Rollback the transaction in case of integrity error
    #     print(f"IntegrityError during user registration: {e}")
    #    raise HTTPException(status_code=400, detail="Email address already registered.")
    except requests.exceptions.RequestException as e:
        print(f"Error during GitHub authentication: {e}")
        raise HTTPException(status_code=500, detail="Error during GitHub authentication")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")
    
#general Login and reg
@app.post('/register', response_model=schemas.Token)
def create_user(request: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = auth.hash_password(request.password)
    new_user = User(
        first_name=request.first_name,
        last_name=request.last_name,
        email=request.email,
        password_hash=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Generate a JWT token
    access_token = create_access_token(data={"user_id": new_user.id})

    return {"access_token": access_token, "token_type": "bearer"}

@app.post('/login', response_model=schemas.Token)
def login(request: schemas.UserLogin, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Invalid Credentials")
    if not auth.verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incorrect password")

    # Generate a JWT token
    access_token = auth.create_access_token(data={"user_id": user.id})

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=schemas.User) 
def get_current_user(current_user: schemas.User = Depends(auth.get_current_user)):
    """
    Endpoint to get the current user's information.
    Requires a valid access token in the Authorization header.
    """
    return current_user

@app.get("/authorized") 
def authorized_route(current_user: schemas.User = Depends(auth.get_current_user)):
    """
    This route requires a valid access token.
    """
    return {"message": "You are authorized"}

#web - socket
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
        


