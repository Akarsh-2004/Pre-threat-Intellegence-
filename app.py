from flask import Flask
from app_routes import setup_routes  # Import function from app_routes.py

app = Flask(__name__)

setup_routes(app)  # Attach routes to Flask app

if __name__ == "__main__":
    from waitress import serve  # Waitress is better for Windows/Render
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
