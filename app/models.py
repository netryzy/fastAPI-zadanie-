from pydantic import BaseModel

class Movietop(BaseModel):
    name: str
    id: int
    cost: int
    director: str
    is_oscar_winner: bool | None = None
    description: str | None = None  
    image_filename: str | None = None  

class LoginRequest(BaseModel):
    username: str
    password: str