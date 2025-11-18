from fastapi import FastAPI, Form, UploadFile, File, Request, Response, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.models import Movietop, LoginRequest
from typing import Annotated, Optional
import os
import uuid
from datetime import datetime, timedelta
from pydantic import BaseModel
import jwt  

app = FastAPI()

#папка для загрузки файлов
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# папка для статических файлов
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

users = {
    "admin": "password123",
    "user": "user123"
}

# Хранилище активных сессий в памяти (для cookie)
sessions = {}

# Хранилище истории всех сессий 
session_history = []

# Время жизни сессии - 2 минуты
SESSION_TIME = 120

# JWT настройки
JWT_SECRET = "your-secret-key-for-jwt-tokens"
JWT_ALGORITHM = "HS256"

# JWT аутентификация
security = HTTPBearer()

# Функция для проверки сессии (cookie)
async def get_current_user_session(request: Request):
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

# Функция для проверки JWT токена
async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Задание Г.5: Проверка JWT токена в заголовке Authorization с использованием PyJWT
    """
    token = credentials.credentials
    try:
        # Используем правильные параметры для декодирования
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True}
        )
        username = payload.get("username")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
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
    <img src="https://avatars.mds.yandex.net/get-altay/1678797/2a00000169243856fe21aa73fa990f4d0c35/XXL_height" width="400">
</body>
</html>
"""

# HTML форма для входа через cookie 
login_cookie_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему (Cookie)</title>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Вход в систему (Cookie аутентификация)</h1>
    <form action="/login-cookie" method="post">
        <div>
            <label for="username">Имя пользователя:</label><br>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div>
            <label for="password">Пароль:</label><br>
            <input type="password" id="password" name="password" required>
        </div>
        
        <br>
        <button type="submit">Войти через Cookie</button>
    </form>
    <p><small>Тестовые пользователи: admin/password123 или user/user123</small></p>
    <br>
    <a href="/user">Перейти в профиль</a>
    <br>
    <a href="/add-movie-cookie">Добавить фильм (Cookie)</a>
    <br><br>
    <a href="/login-jwt">Войти через JWT</a>
</body>
</html>
"""

# HTML форма для получения JWT токена
login_jwt_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Получить JWT токен</title>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Получить JWT токен</h1>
    <form id="loginForm">
        <div>
            <label for="username">Имя пользователя:</label><br>
            <input type="text" id="username" name="username" required value="admin">
        </div>
        
        <div>
            <label for="password">Пароль:</label><br>
            <input type="password" id="password" name="password" required value="password123">
        </div>
        
        <br>
        <button type="submit">Получить JWT токен</button>
    </form>
    
    <div id="result" style="margin-top: 20px; display: none;"></div>
    
    <br>
    <a href="/add-movie-jwt">Добавить фильм (JWT)</a>
    <br><br>
    <a href="/login-cookie">Войти через Cookie</a>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = {
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            };
            
            try {
                const response = await fetch('/login-jwt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                const resultDiv = document.getElementById('result');
                
                if (response.ok) {
                    resultDiv.innerHTML = `
                        <h3 style="color: green;">Токен успешно получен!</h3>
                        <p><strong>Пользователь:</strong> ${result.user}</p>
                        <p><strong>Токен:</strong> <code style="word-break: break-all; background: #f5f5f5; padding: 10px; display: block;">${result.token}</code></p>
                        <p><strong>Истекает:</strong> ${result.expires_at}</p>
                        <button onclick="copyToken('${result.token}')" style="padding: 10px; margin: 10px 0;">Скопировать токен</button>
                    `;
                    resultDiv.style.display = 'block';
                } else {
                    resultDiv.innerHTML = `<h3 style="color: red;">Ошибка:</h3><p>${result.message}</p>`;
                    resultDiv.style.display = 'block';
                }
            } catch (error) {
                console.error('Error:', error);
            }
        });
        
        function copyToken(token) {
            navigator.clipboard.writeText(token).then(() => {
                alert('Токен скопирован в буфер обмена!');
            });
        }
    </script>
</body>
</html>
"""

# HTML с формой для добавления фильмов 
add_movie_jwt_html = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Добавить фильм (JWT)</title>
    <style>
        .hidden { display: none; }
    </style>
</head>
<body>
    <a href="/">← На главную</a>
    <h1>Добавить новый фильм (JWT аутентификация)</h1>
    
    <div>
        <h3>JWT Аутентификация</h3>
        <p>Для добавления фильма необходимо получить JWT токен на странице <a href="/login-jwt">/login-jwt</a></p>
        <div>
            <label for="jwt-token">JWT Токен:</label><br>
            <input type="text" id="jwt-token" style="width: 500px; margin: 5px 0;" 
                   placeholder="Вставьте сюда JWT токен полученный из /login-jwt">
            <br>
            <button type="button" onclick="saveToken()">Сохранить токен</button>
            <button type="button" onclick="clearToken()">Очистить токен</button>
        </div>
        <p id="token-status">Токен не установлен</p>
    </div>
    
    <div id="form-section">
        <p>Статус: <span id="auth-status">Токен не установлен</span></p>
        
        <form id="movie-form" class="hidden">
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
    </div>
    
    <br>
    <a href="/login-jwt">Получить JWT токен</a>

    <script>
        // Убрана проверка при загрузке - теперь токен НЕ загружается автоматически
        function checkToken() {
            const token = document.getElementById('jwt-token').value.trim();
            
            if (token) {
                document.getElementById('token-status').textContent = 'Токен введен (нажмите "Сохранить токен")';
                document.getElementById('token-status').style.color = 'orange';
                document.getElementById('auth-status').textContent = 'Токен не сохранен';
                document.getElementById('auth-status').style.color = 'orange';
                document.getElementById('movie-form').classList.add('hidden');
            } else {
                document.getElementById('token-status').textContent = 'Токен не установлен';
                document.getElementById('token-status').style.color = 'red';
                document.getElementById('auth-status').textContent = 'Установите JWT токен для добавления фильмов';
                document.getElementById('auth-status').style.color = 'red';
                document.getElementById('movie-form').classList.add('hidden');
            }
        }
        
        function saveToken() {
            const token = document.getElementById('jwt-token').value.trim();
            
            if (token) {
                // Токен сохраняется только при явном нажатии кнопки
                localStorage.setItem('jwt_token', token);
                document.getElementById('token-status').textContent = 'Токен сохранен!';
                document.getElementById('token-status').style.color = 'green';
                document.getElementById('movie-form').classList.remove('hidden');
                document.getElementById('auth-status').textContent = 'Готов к отправке с JWT токеном';
                document.getElementById('auth-status').style.color = 'green';
                alert('Токен сохранен! Теперь вы можете добавить фильм.');
            } else {
                alert('Введите JWT токен перед сохранением');
            }
        }
        
        function clearToken() {
            localStorage.removeItem('jwt_token');
            document.getElementById('jwt-token').value = '';
            document.getElementById('token-status').textContent = 'Токен очищен';
            document.getElementById('token-status').style.color = 'red';
            document.getElementById('movie-form').classList.add('hidden');
            document.getElementById('auth-status').textContent = 'Токен не установлен';
            document.getElementById('auth-status').style.color = 'red';
            alert('Токен удален');
        }
        
        document.getElementById('movie-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const token = localStorage.getItem('jwt_token');
            if (!token) {
                alert('JWT токен не установлен! Получите токен на странице /login-jwt');
                return;
            }
            
            const name = document.getElementById('name').value.trim();
            const director = document.getElementById('director').value.trim();
            const cost = document.getElementById('cost').value;
            
            if (!name || !director || !cost) {
                alert('Заполните все обязательные поля: название, режиссер и бюджет');
                return;
            }
            
            const formData = new FormData();
            formData.append('name', name);
            formData.append('director', director);
            formData.append('cost', cost);
            formData.append('is_oscar_winner', document.getElementById('is_oscar_winner').checked);
            
            const descriptionFile = document.getElementById('description_file').files[0];
            if (descriptionFile) formData.append('description_file', descriptionFile);
            
            const imageFile = document.getElementById('image').files[0];
            if (imageFile) formData.append('image', imageFile);
            
            try {
                const response = await fetch('/add-movie-jwt', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    },
                    body: formData
                });
                
                if (response.ok) {
                    const result = await response.text();
                    document.body.innerHTML = result;
                } else {
                    const error = await response.json();
                    alert('Ошибка: ' + error.detail);
                }
            } catch (error) {
                alert('Ошибка при отправке формы');
            }
        });
        
        // При загрузке страницы проверяем только поле ввода, НЕ localStorage
        document.getElementById('jwt-token').addEventListener('input', checkToken);
        
        // Инициализация при загрузке
        window.onload = function() {
            document.getElementById('jwt-token').value = '';
            checkToken();
        };
    </script>
</body>
</html>
"""

movies_data = [
    Movietop(name="Однажды в Голливуде", id=1, cost=90000000, director="Квентин Тарантино"),
    Movietop(name="1+1", id=2, cost=9500000, director="Оливье Накаш"),
    Movietop(name="Бойцовский клуб", id=3, cost=63000000, director="Дэвид Финчер"),
    Movietop(name="Брат", id=4, cost=99600, director="Алексей Балабанов"),
    Movietop(name="Зеленая книга", id=5, cost=23000000, director="Питер Фаррелли"),
    Movietop(name="Остров проклятых", id=6, cost=80000000, director="Мартин Скорсезе"),
    Movietop(name="Бесславные ублюдки", id=7, cost=70000000, director="Квентин Тарантино"),
    Movietop(name="Жмурки", id=8, cost=77000, director="Алексей Балабанов"),
    Movietop(name="Криминальное чтиво", id=9, cost=8000000, director="Квентин Тарантино"),
    Movietop(name="Реквием по мечте", id=10, cost=4500000, director="Даррен Аронофски")
]

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
        <h2>Cтраницы:</h2>
        
        <h3>Задание А:</h3>
        <ul>
            <li><a href="/study">Об учебном заведении</a></li>
            <li><a href="/movietop/">Список всех фильмов (JSON)</a></li>
            <li><a href="/movietop/Однажды в Голливуде">Фильм "Однажды в Голливуде"</a></li>
        </ul>
        
        <h3>Задание Б:</h3>
        <ul>
            <li><a href="/movies-with-images/">Фильмы с обложками</a></li>
        </ul>
        
        <h3>Cookie Аутентификация (Задание В):</h3>
        <ul>
            <li><a href="/login-cookie">Вход через Cookie</a></li>
            <li><a href="/user">Профиль пользователя</a></li>
        </ul>
        
        <h3>JWT Аутентификация (Задание Г):</h3>
        <ul>
            <li><a href="/login-jwt">Получить JWT токен</a></li>
            <li><a href="/add-movie-jwt">Добавить фильм (JWT)</a></li>
        </ul>
    </body>
    </html>
    """)

# Задание А.2 - Информация об учебном заведении
@app.get("/study", response_class=HTMLResponse)
async def study_information():
    return HTMLResponse(study_html)

#Получить все фильмы
@app.get("/movietop/")
async def get_all_movies():
    return movies_data

#Получить фильм по названию
@app.get("/movietop/{movie_name}")
async def get_movie(movie_name: str):
    for movie in movies_data:
        if movie.name.lower() == movie_name.lower():
            return movie
    
    return {"error": "Фильм не найден"}

# JWT аутентификация aорма для добавления фильмов
@app.get("/add-movie-jwt", response_class=HTMLResponse)
async def add_movie_jwt_form():
    """
    Форма добавления фильмов защищена JWT
    """
    return HTMLResponse(add_movie_jwt_html)

# JWT аутентификация 
@app.post("/add-movie-jwt")
async def create_movie_jwt(
    name: str = Form(...),
    director: str = Form(...),
    cost: int = Form(...),
    is_oscar_winner: bool = Form(False),
    description_file: Annotated[UploadFile, File()] = None,
    image: Annotated[UploadFile, File()] = None,
    username: str = Depends(verify_jwt_token)
):
    # Создаем новый ID
    new_id = max(movie.id for movie in movies_data) + 1 if movies_data else 1
    
    # загрузка описания из файла
    description = None
    if description_file and description_file.filename:
        try:
            content = await description_file.read()
            description = content.decode('utf-8')
        except Exception as e:
            description = f"Ошибка чтения файла описания: {str(e)}"
    
    # загрузка изображения
    image_filename = None
    if image and image.filename:
        file_extension = image.filename.split('.')[-1]
        image_filename = f"movie_jwt_{new_id}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, image_filename)
        
        content = await image.read()
        with open(file_path, "wb") as buffer:
            buffer.write(content)
    
    # новый фильм
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
    
    return HTMLResponse(f"""
    <html>
    <body>
        <a href="/">← На главную</a>
        <h1>Фильм успешно добавлен с JWT аутентификацией!</h1>
        <p><strong>Название:</strong> {name}</p>
        <p><strong>Режиссер:</strong> {director}</p>
        <p><strong>Бюджет:</strong> ${cost:,}</p>
        <p><strong>Оскар:</strong> {'Да' if is_oscar_winner else 'Нет'}</p>
        <p><strong>Описание:</strong> {description[:100] + '...' if description and len(description) > 100 else description or 'Не добавлено'}</p>
        <p><strong>Добавлен пользователем:</strong> {username} (JWT аутентификация)</p>
        <br>
        <a href="/add-movie-jwt">Добавить еще один фильм</a>
        <br>
        <a href="/movies-with-images/">Посмотреть все фильмы</a>
    </body>
    </html>
    """)

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
        <a href="/add-movie-cookie">Добавить новый фильм (Cookie)</a>
        <br>
        <a href="/add-movie-jwt">Добавить новый фильм (JWT)</a>
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

# Cookie аутентификация - Маршрут входа
@app.get("/login-cookie", response_class=HTMLResponse)
async def login_cookie_page():
    return HTMLResponse(login_cookie_html)

@app.post("/login-cookie")
async def login_cookie(
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
            <a href="/login-cookie">Вернуться к форме входа</a>
        </body>
        </html>
        """)
    
    # Создаем уникальный session_token
    session_token = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(seconds=SESSION_TIME)
    
    # Сохраняем активную сессию
    sessions[session_token] = {
        "username": username,
        "created_at": datetime.now(),
        "expires_at": expires_at
    }
    
    # Сохраняем в историю сессий (общий список для всех пользователей)
    session_history.append({
        "username": username,
        "session_token": session_token,
        "login_time": datetime.now().isoformat(),
        "expires_at": expires_at.isoformat(),
        "status": "active"
    })
    
    # Устанавливаем cookie и перенаправляем на главную страницу
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=SESSION_TIME
    )
    
    return response

# Защищенный маршрут профиля
@app.get("/user")
async def user_profile(request: Request):

    # Проверяем авторизацию
    username = await get_current_user_session(request)
    
    # Получаем текущую сессию для информации
    session_token = request.cookies.get("session_token")
    current_session = sessions[session_token]
    
    # Возвращаем данные пользователя, историю всех сессий и все фильмы
    return {
        "user_info": {
            "username": current_session["username"],
            "current_login_time": current_session["created_at"].isoformat(),
            "current_session_expires": current_session["expires_at"].isoformat(),
            "current_session_token": session_token,
            "auth_type": "cookie"
        },
        "session_history": session_history,  # Полный список всех заходов всех пользователей
        "movies": [dict(movie) for movie in movies_data]
    }

# для получения токена
@app.get("/login-jwt", response_class=HTMLResponse)
async def login_jwt_page():
    return HTMLResponse(login_jwt_html)

# Маршрут входа через JSON
@app.post("/login-jwt")
async def login_jwt(login_data: LoginRequest):

    # Проверяем логин и пароль
    if login_data.username not in users or users[login_data.username] != login_data.password:
        return JSONResponse(
            content={"message": "Неверные учетные данные"},
            status_code=401
        )
    
    # Генерируем JWT токен с использованием timestamp 
    current_time = datetime.now()
    expiration_time = current_time + timedelta(seconds=SESSION_TIME)
    
    payload = {
        "username": login_data.username,
        "exp": int(expiration_time.timestamp()),  
        "iat": int(current_time.timestamp())      
    }
    
    # Используем jwt.encode из PyJWT
    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "message": "Успешный вход", 
        "user": login_data.username,
        "token": jwt_token,
        "expires_at": expiration_time.isoformat()
    }


#12345