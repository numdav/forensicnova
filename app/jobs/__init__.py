"""ForensicNova — async job management.

Public exports:
    JobManager : filesystem-persisted, thread-safe job state store.

Status & phase constants live in app.jobs.manager.
"""
from app.jobs.manager import JobManager  # noqa: F401
