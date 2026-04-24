"""ForensicNova dashboard package.

Exports the Flask blueprint mounted at /dashboard/*.

The blueprint is:
  - Session-authenticated (cookie-based), NOT token-authenticated.
  - Protected by Flask-WTF CSRFProtect (HTML form attack surface).
  - Wired to templates in app/dashboard/templates/ via template_folder
    passed at Blueprint construction time.

Design note: we intentionally keep templates, forms, routes, and the
keystone auth helper all inside this package (not at app/templates/
top level).  Rationale: self-containment — removing the blueprint
removes the whole dashboard in one delete, nothing gets orphaned.
"""
from app.dashboard.routes import dashboard_bp

__all__ = ["dashboard_bp"]
