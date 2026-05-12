import os
import pytest
from fastapi.testclient import TestClient

os.environ["BEARER_TOKEN"] = "test-token"

from backend.app import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
