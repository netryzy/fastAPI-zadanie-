from fastapi import FastAPI, Form, UploadFile, File, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Annotated
import os
import uuid
from datetime import datetime, timedelta
from app.models import Movietop

app = FastAPI()

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

study_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Учебное заведение - Информация</title>
</head>
<body>
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
    <h1>Добавить новый фильм</h1>
    <form action="/add-movie/" method="post" enctype="multipart/form-data">
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

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/study",  response_class=HTMLResponse)
async def study_information():
    return study_html

@app.get("/movietop/")
async def get_all_movies():
    return movies_data

@app.get("/movietop/{movie_name}")
async def get_movie(movie_name: str):
    for movie in movies_data:
        if movie.name.lower() == movie_name.lower():
            return movie
    
    return {"error": "Фильм не найден"}

@app.get("/add-movie/", response_class=HTMLResponse)
async def add_movie_form():
    return add_movie_html

# Обработчик формы с загрузкой файлов
@app.post("/add-movie/")
async def create_movie(
    name: str = Form(...),
    director: str = Form(...),
    cost: int = Form(...),
    description: str = Form(None),
    is_oscar_winner: bool = Form(False),
    image: Annotated[UploadFile, File()] = None
):
    # Создаем новый ID
    new_id = max(movie.id for movie in movies_data) + 1 if movies_data else 1
    
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
        "movie": new_movie
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
        <style>
            .movie-card {
                border: 1px solid #ddd;
                padding: 20px;
                margin: 10px;
                border-radius: 10px;
                display: inline-block;
                width: 300px;
                vertical-align: top;
            }
            .movie-image {
                max-width: 100%;
                height: 200px;
                object-fit: cover;
            }
            .oscar-winner {
                color: gold;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <h1>Все фильмы с обложками</h1>
        <a href="/add-movie/">Добавить новый фильм</a>
        <br><br>
    """
    
    for movie in movies_data:
        image_html = ""
        if movie.image_filename:
            image_html = f'<img src="/uploads/{movie.image_filename}" class="movie-image" alt="{movie.name}">'
        else:
            image_html = '<div style="height: 200px; background: #f0f0f0; display: flex; align-items: center; justify-content: center;">Нет обложки</div>'
        
        oscar_html = ""
        if movie.is_oscar_winner:
            oscar_html = '<p class="oscar-winner">🏆 Лауреат премии Оскар</p>'
        
        description_html = ""
        if movie.description:
            description_html = f'<p><strong>Описание:</strong> {movie.description}</p>'
        
        movie_list_html += f"""
        <div class="movie-card">
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

# 1. Маршрут входа в систему
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
        return JSONResponse(
            content={"message": "Неверные учетные данные"},
            status_code=401
        )
    
    # Создаем уникальный session_token
    session_token = str(uuid.uuid4())
    
    # Сохраняем сессию
    sessions[session_token] = {
        "username": username,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(seconds=SESSION_TIME)
    }
    
    # Устанавливаем cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=SESSION_TIME
    )
    
    return {"message": "Успешный вход", "user": username}

# 2. Защищенный маршрут
@app.get("/user")
async def user_profile(request: Request):
    # Получаем cookie
    session_token = request.cookies.get("session_token")
    
    # Проверяем наличие cookie
    if not session_token:
        return {"message": "Unauthorized"}
    
    # Проверяем валидность сессии
    if session_token not in sessions:
        return {"message": "Unauthorized"}
    
    session = sessions[session_token]
    
    # Проверяем не истекла ли сессия
    if datetime.now() > session["expires_at"]:
        del sessions[session_token]
        return {"message": "Unauthorized"}
    
    # 5. Продлеваем сессию на 2 минуты
    session["expires_at"] = datetime.now() + timedelta(seconds=SESSION_TIME)
    
    # Возвращаем данные пользователя и фильмы
    return {
        "user_info": {
            "username": session["username"],
            "login_time": session["created_at"].isoformat(),
            "session_expires": session["expires_at"].isoformat()
        },
        "movies": [dict(movie) for movie in movies_data]
    }
