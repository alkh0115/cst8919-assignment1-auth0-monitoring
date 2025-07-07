import json 
import sys
import logging
import os

from os import environ as env
from urllib.parse import quote_plus, urlencode
from functools import wraps
from datetime import datetime

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from werkzeug.middleware.proxy_fix import ProxyFix
from opencensus.ext.azure.log_exporter import AzureLogHandler

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Ensure HTTPS redirection behind proxies
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["PREFERRED_URL_SCHEME"] = "https"

# Set up structured logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add Azure Application Insights logging handler if configured
ai_conn_str = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
if ai_conn_str:
    logger.addHandler(AzureLogHandler(connection_string=InstrumentationKey=adbee9dc-ac4a-4f45-a276-220c987fdea8;IngestionEndpoint=https://canadacentral-1.in.applicationinsights.azure.com/;LiveEndpoint=https://canadacentral.livediagnostics.monitor.azure.com/;ApplicationId=9d70bf09-a431-4eb7-affd-d6cb3bd293ad))
else:
    logger.warning("APPLICATIONINSIGHTS_CONNECTION_STRING is not set. Logs will not be sent to Azure Monitor.")

# Configure OAuth with Auth0
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Auth-protected route decorator
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/')
        
        # Log access to protected route
        app.logger.info(f"ACCESS: {request.path} by user_id: {session['user']['sub']}")
        
        return f(*args, **kwargs)
    return decorated

# Attach this logger to the app
app.logger.handlers = logger.handlers
app.logger.setLevel(logger.level)

# Log all requests with user info (if logged in)
@app.before_request
def log_request_info():
    user = session.get("user", {}).get("userinfo", {})
    user_id = user.get("sub", "anonymous")
    logger.info(f"User: {user_id} | Path: {request.path} | IP: {request.remote_addr}")

# Routes
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token["userinfo"]

    user_info = session["user"]
    logger.info(f"LOGIN - user_id: {user_info.get('sub')}, email: {user_info.get('email')}, timestamp: {datetime.utcnow().isoformat()}Z")

    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))

@app.route("/protected")
@requires_auth
def protected():
    user_info = session["user"]
    logger.info(f"ACCESS - user_id: {user_info.get('sub')}, email: {user_info.get('email')}, route: /protected, timestamp: {datetime.utcnow().isoformat()}Z")
    return render_template("protected.html", user=user_info)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f'https://{env.get("AUTH0_DOMAIN")}/v2/logout?' +
        urlencode({
            "returnTo": url_for("home", _external=True),
            "client_id": env.get("AUTH0_CLIENT_ID"),
        }, quote_via=quote_plus)
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
