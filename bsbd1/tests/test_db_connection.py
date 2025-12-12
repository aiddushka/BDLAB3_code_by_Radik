import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

print("Connecting to:", DATABASE_URL)

try:
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    print("✔ Успешное подключение к БД!")

    cur = conn.cursor()

    # Минимальный тест
    cur.execute("SELECT version();")
    print("\n--- PostgreSQL version ---")
    print(cur.fetchone()[0])

    # Проверка таблиц
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
    tables = cur.fetchall()
    print("\n--- Список таблиц ---")
    for t in tables:
        print(" •", t[0])

    # Проверка доступа к employeeaccess
    print("\n--- Пробуем прочитать employeeaccess (ограничено правами RLS/ролей) ---")
    try:
        cur.execute("SELECT employeeid, systemlogin FROM employeeaccess LIMIT 5;")
        rows = cur.fetchall()
        for r in rows:
            print("  ", r)
    except Exception as e:
        print("Ошибка чтения employeeaccess:", e)

    # Проверка вызова простой функции — адаптируй под свою
    print("\n--- Проверка функции get_current_employee_id() ---")
    try:
        cur.execute("SELECT get_current_employee_id();")
        print("Результат:", cur.fetchone()[0])
    except Exception as e:
        print("Ошибка вызова get_current_employee_id():", e)

    cur.close()
    conn.close()

    print("\n✔ Проверка завершена")

except Exception as e:
    print("❌ Ошибка подключения:", e)
