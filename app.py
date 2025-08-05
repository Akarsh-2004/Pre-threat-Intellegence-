from flask import Flask
from app_routes import setup_routes
import os  # <-- MISSING IMPORT

app = Flask(__name__)
setup_routes(app)

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
