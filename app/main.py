from fastapi import FastAPI, Form, UploadFile, File, Request, Response, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated, Optional
import os
import uuid
import base64
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from app.models import Movietop
from pydantic import BaseModel

app = FastAPI()

# Задание А.1 - Запуск на порту 8165 с отслеживанием изменений
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8165, reload=True)

# Создаем папку для загрузки файлов
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Монтируем папку для статических файлов
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Простые данные пользователей
users = {
    "admin": "password123",
    "user": "user123"
}

# Хранилище сессий в памяти
sessions = {}

# Время жизни сессии - 2 минуты
SESSION_TIME = 120

# JWT настройки (для задания Г)
JWT_SECRET = "your-secret-key-for-jwt-tokens"
JWT_ALGORITHM = "HS256"

# JWT аутентификация
security = HTTPBearer()

# Простая реализация JWT без внешних библиотек
class SimpleJWT:
    @staticmethod
    def encode(payload: dict, secret: str, algorithm: str = "HS256") -> str:
        header = {"alg": algorithm, "typ": "JWT"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{signature_encoded}"
    
    @staticmethod
    def decode(token: str, secret: str, algorithms: list = None) -> dict:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid token format")
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Добавляем padding если нужно
            payload_encoded += '=' * (4 - len(payload_encoded) % 4)
            payload_decoded = base64.urlsafe_b64decode(payload_encoded)
            payload = json.loads(payload_decoded)
            
            # Проверяем expiration
            if 'exp' in payload and datetime.now().timestamp() > payload['exp']:
                raise ValueError("Token expired")
                
            return payload
        except Exception as e:
            raise ValueError(f"Invalid token: {str(e)}")

# Функция для проверки сессии
async def get_current_user(request: Request):
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    if session_token not in sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session"
        )
    
    session = sessions[session_token]
    
    if datetime.now() > session["expires_at"]:
        del sessions[session_token]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired"
        )
    
    # Продлеваем сессию
    session["expires_at"] = datetime.now() + timedelta(seconds=SESSION_TIME)
    
    return session["username"]

# Функция для проверки JWT токена (для задания Г.5)
async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Задание Г.5: Проверка JWT токена в заголовке Authorization
    """
    token = credentials.credentials
    try:
        payload = SimpleJWT.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("username")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return username
    except ValueError as e:
        if "expired" in str(e):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

study_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Учебное заведение - Информация</title>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Брянский государственный инженерно-технологический университет</h1>
    <p>Брянский государственный инженерно-технологический университет (БГИТУ) — высшее учебное заведение Брянска. Готовит кадры 
    для лесного хозяйства и лесопромышленного комплекса, для промышленного и гражданского строительства. Выпускает специалистов 
    в области инженерной экологии, ландшафтной архитектуры, государственного и муниципального управления, технологии деревообработки, 
    строительства автомобильных дорог, информационных систем. 
    </p>
    <img src="https://avatars.mds.yandex.net/get-altay/1678797/2a00000169243856fe21aa73fa990f4d0c35/XXL_height">
</body>
</html>
"""

# HTML форма для входа
login_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему</title>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Вход в систему</h1>
    <form action="/login" method="post">
        <div>
            <label for="username">Имя пользователя:</label><br>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div>
            <label for="password">Пароль:</label><br>
            <input type="password" id="password" name="password" required>
        </div>
        
        <br>
        <button type="submit">Войти</button>
    </form>
    <p><small>Тестовые пользователи: admin/password123 или user/user123</small></p>
    <br>
    <a href="/user">Перейти в профиль (после входа)</a>
    <br>
    <a href="/add-movie/">Попробовать добавить фильм (после входа)</a>
    <br><br>
    <h3>JWT Аутентификация (для API):</h3>
    <p>Используйте POST запрос на /login-json с JSON телом для получения JWT токена</p>
    <p>Пример: {"username": "admin", "password": "password123"}</p>
</body>
</html>
"""

#html с формой для добавления фильмов
add_movie_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Добавить новый фильм</title>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Добавить новый фильм</h1>
    <p>Статус: <span id="auth-status">Проверка авторизации...</span></p>
    <form action="/add-movie/" method="post" enctype="multipart/form-data" id="movie-form">
        <div>
            <label for="name">Название фильма:</label><br>
            <input type="text" id="name" name="name" required>
        </div>
        
        <div>
            <label for="director">Режиссер:</label><br>
            <input type="text" id="director" name="director" required>
        </div>
        
        <div>
            <label for="cost">Бюджет фильма:</label><br>
            <input type="number" id="cost" name="cost" min="0" required>
        </div>
        
        <div>
            <label for="description_file">Описание фильма (файл .txt):</label><br>
            <input type="file" id="description_file" name="description_file" accept=".txt">
        </div>
        
        <div>
            <label for="image">Обложка фильма:</label><br>
            <input type="file" id="image" name="image" accept="image/*">
        </div>
        
        <div>
            <input type="checkbox" id="is_oscar_winner" name="is_oscar_winner" value="true">
            <label for="is_oscar_winner">Лауреат премии Оскар</label>
        </div>
        
        <br>
        <button type="submit">Добавить фильм</button>
    </form>
    <br>
    <a href="/movies-with-images/">Посмотреть все фильмы с обложками</a>
    <br>
    <a href="/login">Вход в систему</a>
    
    <script>
        // Проверяем авторизацию при загрузке страницы
        fetch('/user')
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Not authorized');
                }
            })
            .then(data => {
                document.getElementById('auth-status').textContent = 'Авторизован как: ' + data.user_info.username;
            })
            .catch(error => {
                document.getElementById('auth-status').textContent = 'Не авторизован';
                document.getElementById('movie-form').style.display = 'none';
                document.getElementById('auth-status').innerHTML += '<br><a href="/login">Войдите в систему</a> для добавления фильмов';
            });
    </script>
</body>
</html>
"""

movies_data = [
    Movietop(name = "Однажды в Голливуде", id = 1, cost = 90000000, director = "Квентин Тарантино"),
    Movietop(name = "1+1", id = 2, cost = 9500000, director = "Оливье Накаш"),
    Movietop(name = "Бойцовский клуб", id = 3, cost = 63000000, director = "Дэвид Финчер"),
    Movietop(name = "Брат", id = 4, cost = 99600, director = "Алексей Балабанов"),
    Movietop(name = "Зеленая книга", id = 5, cost = 23000000, director = "Питер Фаррелли"),
    Movietop(name = "Остров проклятых", id = 6, cost = 80000000, director = "Мартин Скорсезе"),
    Movietop(name = "Бесславные ублюдки", id = 7, cost = 70000000, director = "Квентин Тарантино"),
    Movietop(name = "Жмурки", id = 8, cost = 77000, director = "Алексей Балабанов"),
    Movietop(name = "Криминальное чтиво", id = 9, cost = 8000000, director = "Квентин Тарантино"),
    Movietop(name = "Реквием по мечте", id = 10, cost = 4500000, director = "Даррен Аронофски")
]

# Модель для JSON данных логина
class LoginRequest(BaseModel):
    username: str
    password: str

# Главная страница с навигацией
@app.get("/")
async def root():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Главная страница</title>
    </head>
    <body>
        <h1>Добро пожаловать!</h1>
        <h2>Доступные страницы:</h2>
        <ul>
            <li><a href="/study">Об учебном заведении</a></li>
            <li><a href="/login">Вход в систему</a></li>
            <li><a href="/user">Профиль пользователя</a></li>
            <li><a href="/movietop/">Список всех фильмов (JSON)</a></li>
            <li><a href="/movies-with-images/">Фильмы с обложками</a></li>
            <li><a href="/add-movie/">Добавить фильм</a></li>
        </ul>
        <h3>Примеры фильмов:</h3>
        <ul>
            <li><a href="/movietop/Брат">Фильм "Брат"</a></li>
            <li><a href="/movietop/Однажды в Голливуде">Фильм "Однажды в Голливуде"</a></li>
            <li><a href="/movietop/1+1">Фильм "1+1"</a></li>
        </ul>
    </body>
    </html>
    """)

# Задание А.2 - Информация об учебном заведении
@app.get("/study",  response_class=HTMLResponse)
async def study_information():
    return study_html

# Задание А.3.3 - Получить все фильмы
@app.get("/movietop/")
async def get_all_movies():
    return movies_data

# Задание А.3.3 - Получить фильм по названию
@app.get("/movietop/{movie_name}")
async def get_movie(movie_name: str):
    for movie in movies_data:
        if movie.name.lower() == movie_name.lower():
            return movie
    
    return {"error": "Фильм не найден"}

# Задание Б - Форма для добавления фильмов (защищена сессиями для веб-интерфейса)
@app.get("/add-movie/", response_class=HTMLResponse)
async def add_movie_form(request: Request):
    """
    Защищенная форма для добавления фильмов
    Требует аутентификацию через сессию
    """
    # Проверяем авторизацию
    try:
        username = await get_current_user(request)
        return add_movie_html
    except HTTPException:
        # Если не авторизован, перенаправляем на страницу входа
        return RedirectResponse(url="/login")

# Задание Б - Обработчик добавления фильмов (только сессии для веб-формы)
@app.post("/add-movie/")
async def create_movie(
    request: Request,
    name: str = Form(...),
    director: str = Form(...),
    cost: int = Form(...),
    is_oscar_winner: bool = Form(False),
    description_file: Annotated[UploadFile, File()] = None,  # Используем UploadFile для файла
    image: Annotated[UploadFile, File()] = None
):
    """
    Задание Б: 
    """
    # Проверяем авторизацию через сессии
    username = await get_current_user(request)
    
    # Создаем новый ID
    new_id = max(movie.id for movie in movies_data) + 1 if movies_data else 1
    
    # Обрабатываем загрузку описания из файла
    description = None
    if description_file and description_file.filename:
        try:
            # Читаем содержимое файла с описанием
            content = await description_file.read()
            description = content.decode('utf-8')
        except Exception as e:
            description = f"Ошибка чтения файла описания: {str(e)}"
    
    # Обрабатываем загрузку изображения
    image_filename = None
    if image and image.filename:
        file_extension = image.filename.split('.')[-1]
        image_filename = f"movie_{new_id}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, image_filename)
        
        content = await image.read()
        with open(file_path, "wb") as buffer:
            buffer.write(content)
    
    # Создаем новый фильм
    new_movie = Movietop(
        id=new_id,
        name=name,
        director=director,
        cost=cost,
        is_oscar_winner=is_oscar_winner,
        description=description,  # Сохраняем описание из файла
        image_filename=image_filename
    )
    
    # Добавляем в список
    movies_data.append(new_movie)
    
    # Возвращаем HTML ответ вместо JSON
    description_preview = description[:100] + "..." if description and len(description) > 100 else description
    return HTMLResponse(f"""
    <html>
    <body>
        <a href="/">← На главную</a>
        <h1>Фильм успешно добавлен!</h1>
        <p><strong>Название:</strong> {name}</p>
        <p><strong>Режиссер:</strong> {director}</p>
        <p><strong>Бюджет:</strong> ${cost:,}</p>
        <p><strong>Оскар:</strong> {'Да' if is_oscar_winner else 'Нет'}</p>
        <p><strong>Описание:</strong> {description_preview if description else 'Не добавлено'}</p>
        <p><strong>Добавлен пользователем:</strong> {username}</p>
        <br>
        <a href="/add-movie/">Добавить еще один фильм</a>
        <br>
        <a href="/movies-with-images/">Посмотреть все фильмы</a>
    </body>
    </html>
    """)

# Задание Г - API endpoint для добавления фильмов с JWT
@app.post("/api/add-movie/")
async def api_create_movie(
    name: str = Form(...),
    director: str = Form(...),
    cost: int = Form(...),
    is_oscar_winner: bool = Form(False),
    description_file: Annotated[UploadFile, File()] = None,
    image: Annotated[UploadFile, File()] = None,
    username: str = Depends(verify_jwt_token)  # Только JWT для API
):
    """
    Задание Г.4-6: API endpoint защищенный JWT токеном
    """
    # Создаем новый ID
    new_id = max(movie.id for movie in movies_data) + 1 if movies_data else 1
    
    # Обрабатываем загрузку описания из файла
    description = None
    if description_file and description_file.filename:
        try:
            # Читаем содержимое файла с описанием
            content = await description_file.read()
            description = content.decode('utf-8')
        except Exception as e:
            description = f"Ошибка чтения файла описания: {str(e)}"
    
    # Обрабатываем загрузку изображения
    image_filename = None
    if image and image.filename:
        file_extension = image.filename.split('.')[-1]
        image_filename = f"movie_{new_id}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, image_filename)
        
        content = await image.read()
        with open(file_path, "wb") as buffer:
            buffer.write(content)
    
    # Создаем новый фильм
    new_movie = Movietop(
        id=new_id,
        name=name,
        director=director,
        cost=cost,
        is_oscar_winner=is_oscar_winner,
        description=description,
        image_filename=image_filename
    )
    
    # Добавляем в список
    movies_data.append(new_movie)
    
    return {
        "message": "Фильм успешно добавлен",
        "movie": new_movie,
        "added_by": username
    }

# Страница со всеми фильмами и обложками
@app.get("/movies-with-images/", response_class=HTMLResponse)
async def movies_with_images():
    movie_list_html = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Все фильмы с обложками</title>
    </head>
    <body>
        <a href="/">← На главную</a>
        <h1>Все фильмы с обложками</h1>
        <a href="/add-movie/">Добавить новый фильм</a>
        <br><br>
    """
    
    for movie in movies_data:
        image_html = ""
        if movie.image_filename:
            image_html = f'<img src="/uploads/{movie.image_filename}" alt="{movie.name}" style="max-width: 100%; height: 200px; object-fit: cover;">'
        else:
            image_html = '<div style="height: 200px; background: #f0f0f0; display: flex; align-items: center; justify-content: center;">Нет обложки</div>'
        
        oscar_html = ""
        if movie.is_oscar_winner:
            oscar_html = '<p style="color: gold; font-weight: bold;">Лауреат премии Оскар</p>'
        
        description_html = ""
        if movie.description:
            # Обрезаем длинное описание для лучшего отображения
            short_description = movie.description[:200] + "..." if len(movie.description) > 200 else movie.description
            description_html = f'<p><strong>Описание:</strong> {short_description}</p>'
        
        movie_list_html += f"""
        <div style="border: 1px solid #ddd; padding: 20px; margin: 10px; border-radius: 10px; display: inline-block; width: 300px; vertical-align: top;">
            <h2>{movie.name}</h2>
            {image_html}
            <p><strong>Режиссер:</strong> {movie.director}</p>
            <p><strong>Бюджет:</strong> ${movie.cost:,}</p>
            {oscar_html}
            {description_html}
        </div>
        """
    
    movie_list_html += """
    </body>
    </html>
    """
    
    return HTMLResponse(content=movie_list_html)

# Задание В.1 - Маршрут входа через форму (сессии)
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return login_html

@app.post("/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    # Проверяем логин и пароль
    if username not in users or users[username] != password:
        return HTMLResponse("""
        <html>
        <body>
            <h1>Ошибка входа</h1>
            <p>Неверные учетные данные</p>
            <a href="/login">Вернуться к форме входа</a>
        </body>
        </html>
        """)
    
    # Создаем уникальный session_token
    session_token = str(uuid.uuid4())
    
    # Сохраняем сессию
    sessions[session_token] = {
        "username": username,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(seconds=SESSION_TIME)
    }
    
    # Устанавливаем cookie и перенаправляем на главную страницу
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=SESSION_TIME
    )
    
    return response

# Задание В.2-3 - Защищенный маршрут профиля (сессии)
@app.get("/user")
async def user_profile(request: Request):
    # Проверяем авторизацию
    username = await get_current_user(request)
    
    # Получаем сессию для информации
    session_token = request.cookies.get("session_token")
    session = sessions[session_token]
    
    # Возвращаем данные пользователя и фильмы
    return {
        "user_info": {
            "username": session["username"],
            "login_time": session["created_at"].isoformat(),
            "session_expires": session["expires_at"].isoformat()
        },
        "movies": [dict(movie) for movie in movies_data]
    }

# Задание Г.1-3 - Маршрут входа через JSON (JWT)
@app.post("/login-json")
async def login_json(
    login_data: LoginRequest
):
    """
    Задание Г.1: Принимает JSON с username и password
    Задание Г.2: Генерирует JWT токен при успешной аутентификации
    Задание Г.3: Возвращает ошибку при неверных учетных данных
    """
    # Проверяем логин и пароль
    if login_data.username not in users or users[login_data.username] != login_data.password:
        return JSONResponse(
            content={"message": "Неверные учетные данные"},
            status_code=401
        )
    
    # Генерируем JWT токен с сроком действия
    expiration_time = datetime.now() + timedelta(seconds=SESSION_TIME)
    payload = {
        "username": login_data.username,
        "exp": expiration_time.timestamp(),  # Используем timestamp для простой реализации
        "iat": datetime.now().timestamp()
    }
    
    jwt_token = SimpleJWT.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "message": "Успешный вход", 
        "user": login_data.username,
        "token": jwt_token,  # JWT токен возвращается в ответе
        "expires_at": expiration_time.isoformat()
    }