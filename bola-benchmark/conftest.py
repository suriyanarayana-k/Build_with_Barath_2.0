"""Never run destructive demo resets against an operator's database."""
import os
import tempfile
from pathlib import Path

_test_directory = tempfile.TemporaryDirectory(prefix="cyberaccess-tests-")
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = (
    os.environ.get("CYBERACCESS_TEST_DATABASE_URL")
    or "sqlite:///" + str(Path(_test_directory.name) / "test.db")
)
os.environ["REDIS_URL"] = ""
os.environ["DEMO_MODE"] = "true"
