import json
import logging
import os
from datetime import datetime
from functools import wraps
from os import environ as env
from urllib.parse import urlencode, quote_plus

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables
env_file = find_dotenv()
if env_file:
    load_dotenv(env_file)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Required for HTTPS behind reverse proxy (Azure Web App)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Force HTTPS links in redirects
app.config["PREFERRED_URL_SCHEME"] = "https"

# Configure basic logging (plain text format)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Initialize OAuth
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Logging each incoming request
@app.before_request
def log_request():
    user = session.get("user", {}).get("userinfo", {})
    user_id = user.get("sub", "anonymous")
    logger.info(f"Request from {user_id} → {request.method} {request.path} from IP {request.remote_addr}")

# Home route
@app.route("/")
def home():
    return render_template("home.html")

# Login route
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

# Auth0 callback
@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token["userinfo"]

    user = session["user"]
    logger.info(f"LOGIN event: user_id={user.get('sub')}, email={user.get('email')}, time={datetime.utcnow().isoformat()}Z")

    return redirect(url_for("dashboard"))

# Authorization decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            logger.warning(f"UNAUTHORIZED access to {request.path} from IP {request.remote_addr}")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated

# Dashboard route
@app.route("/dashboard")
@requires_auth
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))

# Protected route
@app.route("/protected")
@requires_auth
def protected():
    user = session.get("user", {})
    app.logger.info(f'protected_access: {{"user_id":"{user.get("sub")}","email":"{user.get("email")}","timestamp":"{datetime.utcnow().isoformat()}"}}')
    return render_template("protected.html", user=user)

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f'https://{env.get("AUTH0_DOMAIN")}/v2/logout?' + urlencode({
            "returnTo": url_for("home", _external=True),
            "client_id": env.get("AUTH0_CLIENT_ID")
        }, quote_via=quote_plus)
    )

# Run the app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
