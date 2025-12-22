from pydantic import BaseModel

class Signup(BaseModel):
    email: str
    password: str
    terms_accepted: bool

class Login(BaseModel):
    email: str
    password: str

class APILogin(BaseModel):
    key: str
