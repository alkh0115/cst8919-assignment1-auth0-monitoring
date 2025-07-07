import os
import json
import logging

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request
from authlib.integrations.flask_client import OAuth
from functools import wraps
from opencensus.ext.azure.log_exporter import AzureLogHandler

# Load environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

# Configure Auth0
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    api_base_url=f'https://{os.getenv("AUTH0_DOMAIN")}',
    access_token_url=f'https://{os.getenv("AUTH0_DOMAIN")}/oauth/token',
    authorize_url=f'https://{os.getenv("AUTH0_DOMAIN")}/authorize',
    client_kwargs={'scope': 'openid profile email'},
)

# Configure Azure Application Insights logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(AzureLogHandler(connection_string=os.getenv("APPINSIGHTS_CONNECTION_STRING")))

# Auth wrapper
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=os.getenv("AUTH0_CALLBACK_URL"))

@app.route("/callback")
def callback_handling():
    app.logger.info("Callback triggered")
    try:
        token = auth0.authorize_access_token()
        app.logger.info("Access token received")
        resp = auth0.get('userinfo')
        userinfo = resp.json()
        app.logger.info(f"User info: {userinfo}")
        session["user"] = {"userinfo": userinfo}
        return redirect("/dashboard")
    except Exception as e:
        app.logger.error(f"Error in callback: {e}", exc_info=True)
        return "Internal Server Error", 500

@app.route('/dashboard')
@requires_auth
def dashboard():
    user_email = session['user']['email']
    logger.info(f"ACCESS: Protected dashboard accessed by {user_email}")
    return render_template('dashboard.html', user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(
        f'https://{os.getenv("AUTH0_DOMAIN")}/v2/logout?returnTo={url_for("home", _external=True)}&client_id={os.getenv("AUTH0_CLIENT_ID")}'
    )

# Run app locally
if __name__ == "__main__":
    app.run(debug=True)
