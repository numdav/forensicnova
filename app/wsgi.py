"""ForensicNova WSGI entry point.

Invoked by the systemd unit `devstack@forensicnova.service` via:

    ExecStart=/opt/stack/forensicnova/.venv/bin/python -m app.wsgi

The module exposes:
    app     : Flask     — the WSGI application object (for gunicorn
                          which will call `app.wsgi:app`).
    main()  : None      — dev-server entry point.

Why the Flask dev server:
- Only endpoint is /health; zero concurrency concerns.
- Zero extra dependencies beyond Flask itself.
- Minimal moving parts = easier demo and oral defense.

migration path (already decided, no refactor needed):
    ExecStart=/opt/stack/forensicnova/.venv/bin/gunicorn \\
        --bind <host>:<port> --workers 2 app.wsgi:app
The `app` symbol exported here is already gunicorn-ready.
"""
from __future__ import annotations

from app import create_app

# Module-level app object: this is what a production WSGI server
# (gunicorn / uwsgi) imports. Building it at import time is the
# standard WSGI convention.
app = create_app()


def main() -> None:
    """Run Flask's built-in development server.

    debug=False on purpose:
      - no auto-reloader (systemd owns the lifecycle),
      - no Werkzeug debugger PIN exposed on the network.
    """
    cfg = app.config["FORENSICNOVA"]
    app.logger.info(
        "starting dev server on %s:%d", cfg.bind_host, cfg.bind_port
    )
    app.run(host=cfg.bind_host, port=cfg.bind_port, debug=False)


if __name__ == "__main__":
    main()
