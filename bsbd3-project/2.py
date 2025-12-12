import os
import psycopg2
from dotenv import load_dotenv

# Загружаем переменные из .env файла (как в основном приложении)
load_dotenv()

# Конфигурация БД из env (как в основном коде)
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'radik')

# Сервисные credentials (как в change_password из основного кода)
SERVICE_USER = 'postgres'  # Или os.environ.get('SERVICE_DB_USER', 'postgres')
SERVICE_PASS = 'admin'     # Или os.environ.get('SERVICE_DB_PASS', 'admin') — рекомендуется вынести в env для безопасности

def test_db_connection():
    """Тестирует подключение к БД"""
    try:
        # Пытаемся подключиться
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=SERVICE_USER,
            password=SERVICE_PASS,
            host=DB_HOST,
            port=DB_PORT,
            connect_timeout=5  # Таймаут подключения
        )
        
        # Если успешно, выполняем простой запрос для проверки
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        result = cur.fetchone()
        
        cur.close()
        conn.close()
        
        print("✅ Подключение к БД успешно!")
        print(f"Хост: {DB_HOST}:{DB_PORT}")
        print(f"База данных: {DB_NAME}")
        print(f"Пользователь: {SERVICE_USER}")
        print(f"Тестовый запрос вернул: {result}")
        
    except psycopg2.Error as e:
        print("❌ Ошибка подключения к БД:")
        print(f"Код ошибки: {e.pgcode}")
        print(f"Сообщение: {e.pgerror}")
    except Exception as e:
        print("❌ Неизвестная ошибка:")
        print(str(e))

if __name__ == "__main__":
    test_db_connection()