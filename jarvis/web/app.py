"""
J.A.R.V.I.S. Web Interface
Flask + SocketIO — real-time streaming chat
"""

import os
import threading
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from ..core import JarvisSession

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", os.urandom(32).hex())
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# One session per connected client, keyed by socket session ID
_sessions: dict[str, JarvisSession] = {}
_sessions_lock = threading.Lock()


def _get_session(sid: str) -> JarvisSession:
    with _sessions_lock:
        if sid not in _sessions:
            _sessions[sid] = JarvisSession()
        return _sessions[sid]


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("connect")
def on_connect():
    _get_session(socketio.server.manager.sid)  # pre-create
    emit("status", {"message": "JARVIS online. All systems nominal."})


@socketio.on("disconnect")
def on_disconnect():
    from flask import request
    with _sessions_lock:
        _sessions.pop(request.sid, None)


@socketio.on("message")
def on_message(data):
    from flask import request
    sid = request.sid
    user_input = data.get("text", "").strip()
    if not user_input:
        return

    session = _get_session(sid)
    emit("thinking", {})

    def on_chunk(chunk: str):
        socketio.emit("chunk", {"text": chunk}, to=sid)

    try:
        session.chat(user_input, on_chunk=on_chunk)
        socketio.emit("done", {}, to=sid)
    except Exception as e:
        socketio.emit("error", {"message": str(e)}, to=sid)


@socketio.on("clear")
def on_clear():
    from flask import request
    session = _get_session(request.sid)
    session.reset()
    emit("status", {"message": "Conversation history cleared."})


def run_web(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Start the JARVIS web server."""
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
