import json
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

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Initialize app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Register ProxyFix right **after** creating the Flask app
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Force Flask to generate https:// links
app.config["PREFERRED_URL_SCHEME"] = "https"

# Set up structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add Azure Application Insights handler to send logs to Azure Monitor
# Requires APPINSIGHTS_CONNECTION_STRING in environment variables
#from opencensus.ext.azure.log_exporter import AzureLogHandler
#logger.addHandler(
#    AzureLogHandler(
#        connection_string=os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
#    )
#)

# Initialize OAuth
oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Decorator for protected routes
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            logger.warning(f"UNAUTHORIZED ACCESS ATTEMPT - IP: {request.remote_addr}, timestamp: {datetime.utcnow().isoformat()}Z")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.before_request
def log_request_info():
    user = session.get("user", {}).get("userinfo", {})
    user_id = user.get("sub", "anonymous")
    app.logger.info(f"User: {user_id} | Path: {request.path} | IP: {request.remote_addr}")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

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
        f'https://{env.get("AUTH0_DOMAIN")}/v2/logout?'
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    app.run()