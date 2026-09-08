"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

current_dir = Path(__file__).parent
teachers_file = current_dir / "teachers.json"
auth_secret = os.environ.get("TEACHER_AUTH_SECRET", "development-only-change-me").encode()
bearer_scheme = HTTPBearer(auto_error=False)
token_lifetime_seconds = 8 * 60 * 60


class LoginRequest(BaseModel):
    username: str
    password: str


def load_teachers():
    with teachers_file.open(encoding="utf-8") as file:
        return json.load(file)


def verify_password(password, stored_password):
    salt = bytes.fromhex(stored_password["salt"])
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, stored_password["iterations"]
    ).hex()
    return hmac.compare_digest(password_hash, stored_password["hash"])


def create_token(username):
    expires_at = int(time.time()) + token_lifetime_seconds
    payload = f"{username}:{expires_at}".encode()
    signature = hmac.new(auth_secret, payload, hashlib.sha256).digest()
    encoded_payload = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{encoded_payload}.{encoded_signature}"


def get_current_teacher(credentials: HTTPAuthorizationCredentials = None):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Teacher login required")

    try:
        encoded_payload, encoded_signature = credentials.credentials.split(".")
        padding = "=" * (-len(encoded_payload) % 4)
        payload = base64.urlsafe_b64decode(encoded_payload + padding)
        expected_signature = hmac.new(auth_secret, payload, hashlib.sha256).digest()
        supplied_signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        username, expires_at = payload.decode().split(":", 1)
        if not hmac.compare_digest(supplied_signature, expected_signature):
            raise ValueError
        if int(expires_at) <= time.time():
            raise HTTPException(status_code=401, detail="Teacher session expired")
        if not any(teacher["username"] == username for teacher in load_teachers()):
            raise ValueError
        return username
    except HTTPException:
        raise
    except (ValueError, TypeError, base64.binascii.Error):
        raise HTTPException(status_code=401, detail="Invalid teacher session")

# Mount the static files directory
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(credentials: LoginRequest):
    teacher = next(
        (teacher for teacher in load_teachers() if teacher["username"] == credentials.username),
        None,
    )
    if teacher is None or not verify_password(credentials.password, teacher["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": create_token(teacher["username"]), "token_type": "bearer"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """Sign up a student for an activity"""
    get_current_teacher(credentials)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
):
    """Unregister a student from an activity"""
    get_current_teacher(credentials)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
