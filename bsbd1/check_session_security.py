import requests
import json
from datetime import datetime


def test_session_security():
    """Тестирует безопасность сессий"""

    # 1. Тестовый вход
    login_url = "http://localhost:5000/login"
    test_data = {
        "username": "testuser",
        "password": "TestPass123!",
        "_csrf_token": "dummy"  # В реальном тесте нужно получить CSRF токен
    }

    session = requests.Session()

    try:
        # 2. Пытаемся войти
        response = session.post(login_url, data=test_data)
        print(f"Login response: {response.status_code}")

        # 3. Проверяем заголовки cookies
        cookies = session.cookies
        print("\n=== COOKIE HEADERS ===")
        for cookie in cookies:
            print(f"Name: {cookie.name}")
            print(f"Value: {cookie.value[:20]}...")
            print(f"HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
            print(f"Secure: {cookie.secure}")
            print(f"SameSite: {cookie.get_nonstandard_attr('SameSite')}")
            print("---")

        # 4. Проверяем маршрут debug (если он есть)
        debug_response = session.get("http://localhost:5000/debug/session")
        if debug_response.status_code == 200:
            print("\n=== SESSION CONTENT ===")
            print(debug_response.text[:1000])

        # 5. Проверяем наличие пароля в sessionStorage/localStorage
        print("\n=== SECURITY CHECKS ===")

        # Проверка через JavaScript (имитация)
        js_checks = """
        // Проверка на клиентской стороне
        console.log("Checking localStorage for password...");
        for (let i = 0; i < localStorage.length; i++) {
            let key = localStorage.key(i);
            if (key.toLowerCase().includes('password')) {
                console.warn("WARNING: Password found in localStorage!");
            }
        }

        // Проверка sessionStorage
        for (let i = 0; i < sessionStorage.length; i++) {
            let key = sessionStorage.key(i);
            if (key.toLowerCase().includes('password')) {
                console.warn("WARNING: Password found in sessionStorage!");
            }
        }

        // Проверка cookies доступных через JavaScript
        if (document.cookie.includes('password')) {
            console.warn("WARNING: Password found in accessible cookies!");
        }
        """
        print(js_checks)

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_session_security()