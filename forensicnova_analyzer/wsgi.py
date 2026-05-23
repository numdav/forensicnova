"""
WSGI entry point for forensicnova_analyzer.

Launched by the systemd unit `devstack@forensicnova-analyzer.service`:

    ExecStart=<venv>/bin/python -m forensicnova_analyzer.wsgi

For real production (post-thesis) this should be served via gunicorn or
uwsgi. For the lab environment and the 50-day thesis window, the Flask
built-in dev server is enough: single-process, optionally multi-threaded,
fine for tests and demos.

Operational notes:
  - bind_host/bind_port are read from the config file (section
    [forensicnova_analyzer]).
  - debug=False always — Flask debug mode exposes an interactive
    debugger via the browser, which is unacceptable in a DFIR context.
  - use_reloader=False — the reloader spawns a child process which
    would confuse systemd (PID changing).
"""

from forensicnova_analyzer import create_app


def main() -> None:
    app = create_app()
    cfg = app.config["FORENSICNOVA_ANALYZER"]
    app.run(
        host=cfg.bind_host,
        port=cfg.bind_port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


# WSGI application factory pattern: some WSGI servers (gunicorn) expect
# an `application` attribute exported at module level.
application = create_app()


if __name__ == "__main__":
    main()
