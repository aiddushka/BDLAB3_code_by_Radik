import psycopg2
import hashlib

# -----------------------------
# Конфигурация
# -----------------------------
DB_URL = "postgresql://postgres:admin@localhost:5432/radik"

login = "i.ivanov"
password = "StrongP@ssw0rd!"

# -----------------------------
# Подключение к базе
# -----------------------------
def get_db_connection():
    try:
        conn = psycopg2.connect(DB_URL)
        conn.autocommit = True
        return conn
    except Exception as e:
        print(f"❌ Ошибка подключения к БД: {e}")
        return None

# -----------------------------
# Проверка пароля
# -----------------------------
def test_password_verification():
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cur = conn.cursor()
        # Получаем хеш пароля из БД
        cur.execute("""
            SELECT employeeid, passwordhash
            FROM employeeaccess
            WHERE systemlogin = %s
              AND isactive = TRUE
        """, (login,))
        row = cur.fetchone()
        
        if row is None:
            print(f"❌ Пользователь '{login}' не найден или неактивен")
            return
        
        employee_id, password_hash_db = row
        
        # Считаем MD5-хеш введённого пароля
        password_hash_input = hashlib.md5(password.encode('utf-8')).hexdigest()
        
        if password_hash_input == password_hash_db:
            print(f"✅ Пароль верный! Employee ID: {employee_id}")
        else:
            print(f"❌ Неверный пароль для '{login}'")
    
    except Exception as e:
        print(f"❌ Ошибка при проверке пароля: {e}")
    finally:
        cur.close()
        conn.close()

# -----------------------------
# Главная функция
# -----------------------------
def main():
    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ НАЧАТО")
    print("=" * 60)
    
    test_password_verification()
    
    print("\n" + "=" * 60)
    print("✅ ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("=" * 60)

if __name__ == "__main__":
    main()
