"""Deliberately-vulnerable demo app - every finding here is planted on
purpose to demonstrate/test VibeCheck. Never deploy this."""
import hashlib

from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = True  # VIBE-SEC-08: debug mode left enabled

# VIBE-SEC-01: hardcoded vendor-shaped API key
SECRET_API_KEY = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123456"


@app.after_request
def add_cors_headers(response):
    # VIBE-SEC-07: wildcard CORS origin combined with credentials
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


def hash_password(password):
    # VIBE-SEC-09: password hashed with a broken algorithm
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
