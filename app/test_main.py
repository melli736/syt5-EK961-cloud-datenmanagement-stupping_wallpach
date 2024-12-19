from fastapi.testclient import TestClient

from .main import app

from urllib.parse import urlencode


client = TestClient(app)


def test_clear_all():
    response = client.delete("/clear")

    assert response.status_code == 200

    
def test_register():
    payload = {
        "username": "melli",
        "password": "pass",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = client.put("/register", data=urlencode(payload), headers=headers)

    assert response.status_code == 200

    
def test_login():
    payload = {
        "username": "melli",
        "password": "pass"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = client.post("/login", data=urlencode(payload), headers=headers)

    assert response.status_code == 200
    assert "access_token" in response.json()  # Assuming it returns an access token
    assert "token_type" in response.json()


def test_login_false():
    payload = {
        "username": "melli",
        "password": "pass1"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = client.post("/login", data=urlencode(payload), headers=headers)

    assert response.status_code == 401
    assert not "access_token" in response.json()  # Assuming it returns an access token
    assert not "token_type" in response.json()


