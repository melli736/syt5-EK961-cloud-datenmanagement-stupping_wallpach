from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext
import jwt


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "89abc386a68212457798491089d869a86d8c20ce217fb3821fec9b1d851a27a0"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # TODO: Add pepper
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    # TODO: Add pepper
    return pwd_context.hash(password)


def create_jwt_token(to_encode: dict[str, any], expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
