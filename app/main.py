from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from app.models import Movietop
import uvicorn

app = FastAPI()

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


