# AuthServices
для запуска: docker-compose up -d

API:

1. localhost:8080/register?email=nikolas@yandex.ru&password=q1w2e3 пример запроса на регистрацию пользователя. Возвращает GUID.

2. localhost:8080/login?GUID=4044188132&password=q1w2e3 генерирует два токена авторизации и устанавливает их в cookie.

3. localhost:8080/ проверка на валидность access токена

4. localhost:8080/refresh проводит операцию refresh для access токена.