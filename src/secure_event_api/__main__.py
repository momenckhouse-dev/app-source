"""Local development entrypoint. Containers run gunicorn instead (see Dockerfile)."""

import os

from secure_event_api.app import create_app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.getenv("PORT", "8080")))
