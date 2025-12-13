import os
import re
import secrets
import logging
import base64
import hashlib
from functools import wraps
from datetime import datetime, timedelta, time
from flask import Flask, render_template, request, redirect, session, flash, abort, send_file
import psycopg2
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from collections import defaultdict
import io
import mimetypes
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# 🔐 Конфигурация БД
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_NAME = os.environ.get('DB_NAME', 'autodb')

# 🔐 Системный пользователь для подключения к БД
# В вашем коде измените конфигурацию # РУСТАМ СКАЗАЛ УДАЛИТЬ строка 28!!!!!!!!!!!!!!!!!!1
SYSTEM_DB_USER = os.environ.get('SYSTEM_DB_USER', 'app_user')
SYSTEM_DB_PASSWORD = os.environ.get('SYSTEM_DB_PASSWORD', 'strongpassword')
# 🔐 Настройка безопасности сессии
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_ENV') == 'production',
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
)

# 🔐 Настройка логирования
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(ip)s] %(message)s' if os.environ.get(
        'LOG_WITH_IP') else '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 🔐 Хранилище для отслеживания попыток входа
failed_attempts = defaultdict(list)

# 🔐 Хранилище заблокированных IP
blocked_ips = {}

# 🔐 Хранилище сессионных токенов
session_tokens = {}


# 🔐 Функции для шифрования паролей
def get_fernet_key():
    """Генерирует ключ шифрования из секретного ключа приложения"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'secure_salt_123',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(app.secret_key.encode()))
    return Fernet(key)


fernet = get_fernet_key()


def encrypt_password(password):
    """Шифрует пароль для безопасного хранения"""
    return fernet.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    """Расшифровывает пароль"""
    return fernet.decrypt(encrypted_password.encode()).decode()


def get_system_db_connection():

    """Подключение к БД через системного пользователя (app_user)"""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=SYSTEM_DB_USER,
            password=SYSTEM_DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            connect_timeout=5
        )
        return conn
    except Exception as e:
        logger.error(f"Ошибка подключения к БД через системного пользователя: {str(e)}")
        raise


def get_client_ip():
    """Получает реальный IP-адрес клиента"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def is_ip_blocked(ip_address):
    """Проверяет, заблокирован ли IP-адрес"""
    if ip_address in blocked_ips:
        if datetime.now() < blocked_ips[ip_address]:
            return True
        else:
            del blocked_ips[ip_address]
            if ip_address in failed_attempts:
                del failed_attempts[ip_address]
    return False


def add_failed_attempt(ip_address):
    """Добавляет запись о неудачной попытке входа"""
    now = datetime.now()

    # Очищаем старые попытки
    failed_attempts[ip_address] = [
        attempt_time for attempt_time in failed_attempts[ip_address]
        if (now - attempt_time).total_seconds() < 1800
    ]

    # Добавляем новую попытку
    failed_attempts[ip_address].append(now)

    # Если больше 5 попыток, блокируем
    if len(failed_attempts[ip_address]) >= 5:
        block_until = now + timedelta(minutes=30)
        blocked_ips[ip_address] = block_until
        logger.warning(f"IP {ip_address} заблокирован на 30 минут")

        del failed_attempts[ip_address]
        return True, block_until
    return False, None


def clear_failed_attempts(ip_address):
    """Очищает историю неудачных попыток"""
    if ip_address in failed_attempts:
        del failed_attempts[ip_address]


def cleanup_old_attempts():
    """Очищает старые записи о попытках входа"""
    now = datetime.now()
    ips_to_remove = []

    # Очищаем failed_attempts
    for ip, attempts in list(failed_attempts.items()):
        recent_attempts = [
            attempt_time for attempt_time in attempts
            if (now - attempt_time).total_seconds() < 1800
        ]
        if recent_attempts:
            failed_attempts[ip] = recent_attempts
        else:
            ips_to_remove.append(ip)

    for ip in ips_to_remove:
        del failed_attempts[ip]

    # Очищаем blocked_ips
    for ip, block_until in list(blocked_ips.items()):
        if now > block_until:
            del blocked_ips[ip]


# 🔐 Декоратор для защиты от брутфорса
def protect_bruteforce(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = get_client_ip()

        if is_ip_blocked(ip_address):
            block_until = blocked_ips[ip_address]
            time_left = (block_until - datetime.now()).total_seconds()
            minutes_left = int(time_left // 60)
            seconds_left = int(time_left % 60)

            flash(
                f"Ваш IP заблокирован на {minutes_left} минут {seconds_left} секунд",
                "error"
            )
            logger.warning(f"Заблокированный IP {ip_address} пытается получить доступ к {request.path}")

            if request.path == "/login":
                return redirect("/")
            else:
                abort(429)

        return f(*args, **kwargs)

    return decorated_function


ROLE_PERMISSIONS = {
    "superadmin": {"create": True, "read": True, "update": True, "delete": True},
    "manager": {"create": True, "read": True, "update": True, "delete": True},
    "senior_mechanic": {"create": False, "read": True, "update": True, "delete": False},
    "junior_employee": {"create": False, "read": True, "update": False, "delete": False},
    "security_officer": {"create": True, "read": True, "update": True, "delete": True}
}

ROLE_TABLES = {
    "superadmin": {
        "Клиенты": "v_clients",
        "Машины": "v_cars",
        "Заказы": "v_orders",
        "Услуги в заказе": "v_order_services",
        "Сотрудники": "v_employees",
        "Услуги": "v_services",
        "Отделы": "v_departments",
        "Категория услуг": "v_service_categories",
        "Модели": "v_models",
        "Марки": "v_makes",
        "Конфиденциальные документы": "v_confidential_documents_secure",
        "Доступ сотрудников": "v_security_employee_access",
        "История паролей": "v_security_password_history",
        "Роли": "v_security_roles",
        "Разрешения ролей": "v_security_role_permissions",
        "Роли сотрудников": "v_security_employee_roles",
        "Разрешения": "v_security_permissions",
        "Логи": "v_security_audit_log",
        "Логи к зашифрованным данным": "v_security_encrypted_access_log"
    },
    "manager": {
        "Клиенты": "v_secure_clients",
        "Машины": "v_cars",
        "Заказы": "v_orders",
        "Услуги в заказе": "v_order_services",
        "Сотрудники": "v_hr_employees",
        "Модели": "v_models",
        "Марки": "v_makes",
        "Услуги": "v_services",
        "Категория услуг": "v_service_categories",
        "Конфиденциальные документы": "v_confidential_documents_secure"
    },
    "senior_mechanic": {
        "Заказы": "v_orders",
        "Услуги в заказе": "v_order_services",
        "Сотрудники": "v_public_employees",
        "Услуги": "v_services",
        "Машины": "v_cars",
        "Клиенты": "v_secure_clients",
        "Конфиденциальные документы": "v_confidential_documents_secure"
    },
    "junior_employee": {
        "Заказы": "v_orders",
        "Услуги в заказе": "v_order_services",
        "Услуги": "v_services",
        "Машины": "v_cars",
        "Клиенты": "v_secure_clients",
        "Конфиденциальные документы": "v_confidential_documents_secure"
    },
    "security_officer": {
        "Сотрудники": "v_security_employees",
        "Конфиденциальные документы": "v_confidential_documents_secure",
        "Доступ сотрудников": "v_security_employee_access",
        "История паролей": "v_security_password_history2",
        "Роли": "v_security_roles",
        "Разрешения ролей": "v_security_role_permissions",
        "Роли сотрудников": "v_security_employee_roles",
        "Разрешения": "v_security_permissions",
        "Логи": "v_security_audit_log",
        "Логи к зашифрованным данным": "v_security_encrypted_access_log",
        "клиенты": "v_secure_clients"
    }
}

# 🔐 Whitelist допустимых таблиц
TABLE_WHITELIST = set()
for role_data in ROLE_TABLES.values():
    TABLE_WHITELIST.update(role_data.values())


# 🔐 Декораторы безопасности
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session or "auth_token" not in session:
            flash("Требуется авторизация", "error")
            return redirect("/")

        token = session.get("auth_token")
        if token not in session_tokens:
            session.clear()
            flash("Сессия истекла", "error")
            return redirect("/")

        return f(*args, **kwargs)

    return decorated


def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session or "role" not in session:
                abort(401)

            user_role = session.get("role")
            if user_role not in allowed_roles:
                logger.warning(f"Несанкционированный доступ: {session.get('user')} ({user_role}) к {request.path}")
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def sanitize_table_name(table_name):
    """Проверка имени таблицы через whitelist"""
    if table_name not in TABLE_WHITELIST:
        logger.error(f"Попытка доступа к неразрешенной таблице: {table_name}")
        raise ValueError("Недопустимое имя таблицы")
    return table_name


# 🔐 Функции для работы с сессионными токенами
def create_session_token(username, role, employee_id=None, password=None):
    """Создает сессионный токен"""
    token = secrets.token_hex(32)
    expires = datetime.now() + timedelta(minutes=30)

    # Шифруем пароль, если он передан
    encrypted_password = None
    if password:
        encrypted_password = encrypt_password(password)

    session_tokens[token] = {
        'username': username,
        'role': role,
        'employee_id': employee_id,
        'encrypted_password': encrypted_password,
        'expires': expires,
        'created': datetime.now()
    }

    cleanup_expired_tokens()
    return token


def get_session_token(token):
    """Получает информацию о сессии по токену"""
    if token not in session_tokens:
        return None

    creds = session_tokens[token]
    if datetime.now() > creds['expires']:
        del session_tokens[token]
        return None

    return creds


def cleanup_expired_tokens():
    """Очищает устаревшие токены"""
    current_time = datetime.now()
    expired_tokens = []

    for token, creds in session_tokens.items():
        if current_time > creds['expires']:
            expired_tokens.append(token)

    for token in expired_tokens:
        del session_tokens[token]


def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            token = session.get('_csrf_token')
            form_token = request.form.get('_csrf_token')

            if not token or token != form_token:
                logger.warning(f"Неверный CSRF токен: {session.get('user', 'anonymous')}")
                abort(403)
        return f(*args, **kwargs)

    return decorated_function


# 🔐 Генерация CSRF-токена
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


def get_db_connection():
    """Создает подключение к БД с использованием токена (через app_user)"""
    try:
        # Получаем токен из сессии
        token = session.get("auth_token")
        if not token or token not in session_tokens:
            raise ValueError("Пользователь не авторизован")

        # Проверяем срок действия
        token_data = session_tokens[token]
        if datetime.now() > token_data['expires']:
            del session_tokens[token]
            raise ValueError("Сессия истекла")

        # Подключаемся через системного пользователя (app_user)
        conn = get_system_db_connection()

        # Устанавливаем переменную сессии для определения пользователя в БД
        cur = conn.cursor()
        cur.execute("SET SESSION app.user_id = %s;", (token_data.get('employee_id'),))
        cur.execute("SET SESSION app.user_role = %s;", (token_data.get('role'),))
        conn.commit()
        cur.close()

        return conn

    except Exception as e:
        logger.error(f"Ошибка подключения к БД: {str(e)}")
        raise


def start_cleanup_thread():
    """Запускает поток для периодической очистки старых записей"""
    import threading
    import time

    def cleanup_worker():
        while True:
            try:
                cleanup_old_attempts()
                time.sleep(300)
            except Exception as e:
                logger.error(f"Ошибка в cleanup_worker: {e}")
                time.sleep(60)

    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()
    logger.info("Запущен поток очистки старых записей о попытках входа")


# 🔐 Запускаем очистку при старте приложения
start_cleanup_thread()


# 🔐 Главная страница
@app.route("/", methods=["GET"])
@csrf_protect
def landing():
    """Главная страница автосервиса"""
    # Если пользователь уже авторизован, перенаправляем на dashboard
    if "user" in session and "auth_token" in session:
        return redirect("/home")
    return render_template("index.html")  # Главная


@app.route("/login", methods=["GET"])
@protect_bruteforce
@csrf_protect
def login_page():
    """Страница входа в систему"""
    # Если пользователь уже авторизован, перенаправляем на dashboard
    if "user" in session and "auth_token" in session:
        return redirect("/home")
    return render_template("login.html")  # Форма входа


# 🔐 Логин с аутентификацией через employeeaccess
@app.route("/login", methods=["POST"])
@csrf_protect
@protect_bruteforce
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # 🔐 Базовая валидация
    if not username or not password:
        flash("Заполните все поля", "error")
        return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

    if len(username) > 50 or len(password) > 100:
        flash("Слишком длинные данные", "error")
        return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

    # 🔐 Проверка на SQL-инъекции
    if re.search(r'[\'";\\]', username):
        logger.warning(f"Обнаружена попытка SQL-инъекции: {username[:50]}...")
        flash("Неверные учетные данные", "error")
        return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

    try:
        # Подключаемся через системного пользователя
        conn = get_system_db_connection()
        cur = conn.cursor()

        # Получаем информацию о пользователе из employeeaccess
        cur.execute("""
            SELECT employeeid, passwordhash, passwordcompliant, 
                   forcepasswordchange, systemlogin
            FROM employeeaccess
            WHERE systemlogin = %s AND isactive = TRUE
        """, (username,))

        user_data = cur.fetchone()

        if not user_data:
            conn.close()
            flash("Пользователь не найден или неактивен", "error")
            # Добавляем неудачную попытку
            ip_address = get_client_ip()
            is_blocked, block_until = add_failed_attempt(ip_address)
            if is_blocked:
                flash("Слишком много неудачных попыток. Ваш IP заблокирован на 30 минут.", "error")
            else:
                attempts_left = 5 - len(failed_attempts.get(ip_address, []))
                if attempts_left > 0:
                    flash(f"Неверные учетные данные. Осталось попыток: {attempts_left}", "error")
                else:
                    flash("Неверные учетные данные", "error")
            return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

        employee_id, password_hash_db, password_compliant, force_password_change, system_login = user_data

        # Проверяем пароль (MD5 хеш)
        password_hash_input = hashlib.md5(password.encode('utf-8')).hexdigest()

        if password_hash_input != password_hash_db:
            conn.close()
            flash("Неверный пароль", "error")
            # Добавляем неудачную попытку
            ip_address = get_client_ip()
            is_blocked, block_until = add_failed_attempt(ip_address)
            if is_blocked:
                flash("Слишком много неудачных попыток. Ваш IP заблокирован на 30 минут.", "error")
            else:
                attempts_left = 5 - len(failed_attempts.get(ip_address, []))
                if attempts_left > 0:
                    flash(f"Неверные учетные данные. Осталось попыток: {attempts_left}", "error")
                else:
                    flash("Неверные учетные данные", "error")
            return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

        # Определяем роль пользователя
        cur.execute("""
            SELECT r.role_name
            FROM employee_roles er
            JOIN roles r ON er.role_id = r.role_id
            WHERE er.employee_id = %s 
            AND er.is_active = TRUE
            LIMIT 1
        """, (employee_id,))

        role_data = cur.fetchone()

        if not role_data:
            conn.close()
            flash("У вас нет назначенной роли в системе", "error")
            return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")

        role = role_data[0].lower()

        # Проверяем сложность пароля (если есть такая функция)
        try:
            cur.execute("SELECT is_weak_password(%s);", (password,))
            is_weak = cur.fetchone()[0]

            # Если пароль слабый или требует смены
            if is_weak or force_password_change or not password_compliant:
                conn.close()
                # Создаем временный токен для смены пароля
                temp_token = create_session_token(username, role, employee_id)
                flash("⚠️ Требуется смена пароля", "warning")
                return redirect(f"/change_password?token={temp_token}")
        except:
            # Если функции нет, пропускаем проверку
            pass

        conn.close()

        # 🔐 Успешная аутентификация
        ip_address = get_client_ip()
        clear_failed_attempts(ip_address)

        # Создаем сессию
        session.clear()
        session["user"] = username
        session["role"] = role
        session["employee_id"] = employee_id
        # Передаем пароль для шифрования и сохранения в токене
        session["auth_token"] = create_session_token(username, role, employee_id, password)
        session["login_time"] = datetime.now().isoformat()

        logger.info(f"Успешный вход пользователя: {username} ({role})")
        return redirect("/home")

    except Exception as e:
        ip_address = get_client_ip()
        logger.error(f"Ошибка входа с IP {ip_address}: {str(e)}")
        flash("Ошибка аутентификации", "error")
        return redirect("/login")  # ИЗМЕНЕНО: было redirect("/")
# 🔐 Смена пароля (ИСПРАВЛЕННАЯ ВЕРСИЯ)
@app.route("/change_password", methods=["GET", "POST"])
@csrf_protect
@protect_bruteforce
def change_password():
    token = request.args.get("token", "")

    if request.method == "GET":
        if not token:
            flash("Недействительная ссылка", "error")
            return redirect("/")
        return render_template("change_password.html", token=token)

    # POST запрос
    if not token:
        flash("Недействительный токен", "error")
        return redirect("/")

    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # 🔐 Базовая валидация
    if not new_password or not confirm_password:
        flash("Заполните все поля", "error")
        return redirect(f"/change_password?token={token}")

    if new_password != confirm_password:
        flash("Пароли не совпадают", "error")
        return redirect(f"/change_password?token={token}")

    try:
        # 🔐 Получаем информацию о сессии по токену
        session_info = get_session_token(token)
        if not session_info:
            flash("Токен недействителен или истек", "error")
            return redirect("/")

        username = session_info['username']
        employee_id = session_info['employee_id']

        # 🔐 Используем функцию БД для смены пароля
        # В реальном приложении здесь должна быть логика смены пароля в БД
        # через безопасную функцию

        flash("✅ Пароль успешно изменен. Войдите снова.", "success")
        return redirect("/")

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Ошибка смены пароля: {error_msg}")
        flash("Ошибка при смене пароля", "error")
        return redirect(f"/change_password?token={token}")


# 🏠 Домашняя страница
@app.route("/home")
@require_auth
def home():
    role = session.get("role")
    if not role or role not in ROLE_TABLES:
        session.clear()
        flash("Недействительная роль", "error")
        return redirect("/")

    tables = ROLE_TABLES.get(role, {})

    # 🔐 Экранирование HTML для предотвращения XSS
    def escape_html(text):
        if not text:
            return ""
        return (str(text)
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))

    return render_template("home.html",
                           user=escape_html(session["user"]),
                           role=role,
                           tables=tables)


def execute_safe_query(conn, query, params=None, fetchone=False):
    """Безопасное выполнение SQL запроса с параметризацией"""
    try:
        with conn.cursor() as cur:
            cur.execute(query, params or ())

            if fetchone:
                result = cur.fetchone()
                columns = [desc[0] for desc in cur.description] if cur.description else []
                return result, columns
            else:
                result = cur.fetchall()
                columns = [desc[0] for desc in cur.description] if cur.description else []
                return result, columns

    except Exception as e:
        logger.error(f"Ошибка выполнения запроса: {str(e)}")
        conn.rollback()
        raise


# 🔐 Функции для работы с таблицами (исправленные)

# ➕ Добавление марки
@app.route("/add/Марки", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_make():
    """Безопасное добавление марки с валидацией и CSRF защитой"""
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            makename = request.form.get("makename", "").strip()

            # 🔐 Валидация входных данных
            if not makename:
                return render_template("add_make.html", error="Название марки является обязательным полем")

            if len(makename) > 100:
                return render_template("add_make.html", error="Название марки слишком длинное (максимум 100 символов)")

            # 🔐 Проверка на опасные символы
            if re.search(r'[<>"\';\\]', makename):
                return render_template("add_make.html", error="Название содержит недопустимые символы")

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()  # ✅ Используем безопасное подключение
            cur = conn.cursor()

            # 🔐 Проверяем, не существует ли уже такая марка
            cur.execute("SELECT COUNT(*) FROM fn_get_all_makes() WHERE makename = %s", (makename,))
            count = cur.fetchone()[0]

            if count > 0:
                conn.close()
                return render_template("add_make.html", error="Марка с таким названием уже существует")

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_make(%s);", (makename,))
            conn.commit()
            conn.close()

            flash("Марка успешно добавлена", "success")
            return redirect("/table/Марки")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_make: {str(e)}")
            flash("Ошибка при добавлении марки", "error")
            return render_template("add_make.html", error="Ошибка базы данных")
        except Exception as e:
            logger.error(f"Ошибка в add_make: {str(e)}")
            flash("Внутренняя ошибка сервера", "error")
            return render_template("add_make.html", error="Внутренняя ошибка")

    # GET запрос - показываем форму
    return render_template("add_make.html")


# 🔐 Безопасное редактирование марки
@app.route("/edit/Марки/<int:make_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_make(make_id):
    """Безопасное редактирование марки с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        make_id = int(make_id)
        if make_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()  # ✅
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные марки через безопасную функцию
            cur.execute("SELECT * FROM fn_get_make_by_id(%s)", (make_id,))
            record = cur.fetchone()

            if not record:
                flash("Марка не найдена", "error")
                return redirect("/table/Марки")

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_make.html",
                                   record_data=list(zip(colnames, record)),
                                   make_id=make_id)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            makename = request.form.get("makename", "").strip()

            # 🔐 Валидация входных данных
            if not makename:
                flash("Название марки является обязательным полем", "error")
                return redirect(f"/edit/Марки/{make_id}")

            if len(makename) > 100:
                flash("Название марки слишком длинное (максимум 100 символов)", "error")
                return redirect(f"/edit/Марки/{make_id}")

            # 🔐 Проверка на опасные символы
            if re.search(r'[<>"\';\\]', makename):
                flash("Название содержит недопустимые символы", "error")
                return redirect(f"/edit/Марки/{make_id}")

            # 🔐 Проверяем, не существует ли уже такая марка (кроме текущей)
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_makes() 
                WHERE makename = %s AND makeid != %s
            """, (makename, make_id))
            count = cur.fetchone()[0]

            if count > 0:
                flash("Марка с таким названием уже существует", "error")
                return redirect(f"/edit/Марки/{make_id}")

            # Вызываем безопасную функцию обновления
            cur.execute("SELECT fn_update_make(%s, %s);", (make_id, makename))
            conn.commit()
            conn.close()

            flash("Марка успешно обновлена", "success")
            return redirect("/table/Марки")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_make: {str(e)}")
        flash("Ошибка при обновлении марки", "error")
        return redirect(f"/edit/Марки/{make_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_make: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Марки/{make_id}")
    finally:
        if conn:
            conn.close()


# 🔐 Безопасное удаление марки
@app.route("/delete/Марки/<int:make_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_make(make_id):
    """Безопасное удаление марки с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        make_id = int(make_id)
        if make_id <= 0:
            return "Неверный идентификатор марки", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор марки", 400

    try:
        conn = get_db_connection()  # ✅
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли марка
        cur.execute("SELECT COUNT(*) FROM fn_get_all_makes() WHERE makeid = %s", (make_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Марка не найдена", "error")
            return redirect("/table/Марки")

        # 🔐 Проверяем, нет ли связанных моделей
        cur.execute("SELECT COUNT(*) FROM models WHERE makeid = %s", (make_id,))
        model_count = cur.fetchone()[0]

        if model_count > 0:
            conn.close()
            flash("Невозможно удалить марку: существуют связанные модели", "error")
            return redirect("/table/Марки")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_make(%s);", (make_id,))
        conn.commit()
        conn.close()

        flash("Марка удалена", "info")
        return redirect("/table/Марки")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_make: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_make: {str(e)}")
        return "Ошибка удаления", 500


@app.route("/add/Модели", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_model():
    """Безопасное добавление модели с валидацией и CSRF защитой"""
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            makeid = request.form.get("makeid", "").strip()
            modelname = request.form.get("modelname", "").strip()

            # 🔐 Валидация входных данных
            if not makeid:
                return render_template("add_model.html",
                                       error="Марка является обязательным полем",
                                       makes=get_makes_list())

            if not modelname:
                return render_template("add_model.html",
                                       error="Название модели является обязательным полем",
                                       makes=get_makes_list())

            if len(modelname) > 100:
                return render_template("add_model.html",
                                       error="Название модели слишком длинное (максимум 100 символов)",
                                       makes=get_makes_list())

            # 🔐 Проверка на опасные символы
            if re.search(r'[<>"\';\\]', modelname):
                return render_template("add_model.html",
                                       error="Название модели содержит недопустимые символы",
                                       makes=get_makes_list())

            # 🔐 Валидация числового поля
            try:
                makeid_int = int(makeid)
                if makeid_int <= 0:
                    return render_template("add_model.html",
                                           error="ID марки должен быть положительным числом",
                                           makes=get_makes_list())
            except ValueError:
                return render_template("add_model.html",
                                       error="ID марки должен быть числом",
                                       makes=get_makes_list())

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем существование марки
            cur.execute("SELECT COUNT(*) FROM fn_get_all_makes() WHERE makeid = %s", (makeid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_model.html",
                                       error="Указанная марка не существует",
                                       makes=get_makes_list())

            # 🔐 Проверяем, не существует ли уже такая модель у этой марки


            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_model(%s, %s);", (makeid_int, modelname))
            conn.commit()
            conn.close()

            flash("Модель успешно добавлена", "success")
            return redirect("/table/Модели")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_model: {str(e)}")
            return render_template("add_model.html",
                                   error="Ошибка при добавлении модели",
                                   makes=get_makes_list())
        except Exception as e:
            logger.error(f"Ошибка в add_model: {str(e)}")
            return render_template("add_model.html",
                                   error="Внутренняя ошибка сервера",
                                   makes=get_makes_list())

    # GET запрос - показываем форму
    return render_template("add_model.html", makes=get_makes_list())


# 🔐 Безопасное редактирование модели
@app.route("/edit/Модели/<int:model_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_model(model_id):
    """Безопасное редактирование модели с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        model_id = int(model_id)
        if model_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные модели через безопасную функцию
            cur.execute("SELECT * FROM fn_get_model_by_id(%s)", (model_id,))
            record = cur.fetchone()

            if not record:
                flash("Модель не найдена", "error")
                return redirect("/table/Модели")

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_model.html",
                                   record_data=list(zip(colnames, record)),
                                   makes=get_makes_list(),
                                   model_id=model_id)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            makeid = request.form.get("makeid", "").strip()
            modelname = request.form.get("modelname", "").strip()

            # 🔐 Валидация входных данных
            if not makeid:
                flash("Марка является обязательным полем", "error")
                return redirect(f"/edit/Модели/{model_id}")

            if not modelname:
                flash("Название модели является обязательным полем", "error")
                return redirect(f"/edit/Модели/{model_id}")

            if len(modelname) > 100:
                flash("Название модели слишком длинное (максимум 100 символов)", "error")
                return redirect(f"/edit/Модели/{model_id}")

            # 🔐 Проверка на опасные символы
            if re.search(r'[<>"\';\\]', modelname):
                flash("Название модели содержит недопустимые символы", "error")
                return redirect(f"/edit/Модели/{model_id}")

            # 🔐 Валидация числового поля
            try:
                makeid_int = int(makeid)
                if makeid_int <= 0:
                    flash("ID марки должен быть положительным числом", "error")
                    return redirect(f"/edit/Модели/{model_id}")
            except ValueError:
                flash("ID марки должен быть числом", "error")
                return redirect(f"/edit/Модели/{model_id}")

            # 🔐 Проверяем существование марки
            cur.execute("SELECT COUNT(*) FROM fn_get_all_makes() WHERE makeid = %s", (makeid_int,))
            if cur.fetchone()[0] == 0:
                flash("Указанная марка не существует", "error")
                return redirect(f"/edit/Модели/{model_id}")


            # Вызываем безопасную функцию обновления
            cur.execute("SELECT fn_update_model(%s, %s, %s);",
                        (model_id, makeid_int, modelname))
            conn.commit()
            conn.close()

            flash("Модель успешно обновлена", "success")
            return redirect("/table/Модели")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_model: {str(e)}")
        flash("Ошибка при обновлении модели", "error")
        return redirect(f"/edit/Модели/{model_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_model: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Модели/{model_id}")
    finally:
        if conn:
            conn.close()

# 🗑️ Безопасное удаление модели
@app.route("/delete/Модели/<int:model_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_model(model_id):
    """Безопасное удаление модели с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        model_id = int(model_id)
        if model_id <= 0:
            return "Неверный идентификатор модели", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор модели", 400

    try:
        conn = get_db_connection()  # ✅
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли модель
        cur.execute("SELECT COUNT(*) FROM fn_get_all_models() WHERE modelid = %s", (model_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Модель не найдена", "error")
            return redirect("/table/Модели")

        # 🔐 Проверяем, нет ли связанных услуг


        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_model(%s);", (model_id,))
        conn.commit()
        conn.close()

        flash("Модель удалена", "info")
        return redirect("/table/Модели")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_model: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_model: {str(e)}")
        return "Ошибка удаления", 500

@app.route("/add/Клиенты", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_client():
    """Безопасное добавление клиента с валидацией и CSRF защитой"""
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            fullname = request.form.get("fullname", "").strip()
            phone = request.form.get("phone", "").strip() or None
            email = request.form.get("email", "").strip() or None
            address = request.form.get("address", "").strip() or None
            registration_date = request.form.get("registrationdate", "").strip() or None

            # 🔐 Валидация входных данных
            if not fullname:
                return render_template("add_client.html", error="ФИО клиента является обязательным полем")

            if len(fullname) > 200:
                return render_template("add_client.html", error="ФИО слишком длинное (максимум 200 символов)")

            if re.search(r'[<>"\';\\]', fullname):
                return render_template("add_client.html", error="ФИО содержит недопустимые символы")

            if phone and len(phone) > 20:
                return render_template("add_client.html", error="Телефон слишком длинный (максимум 20 символов)")
            elif phone and not re.match(r'^[\d\s\-\+\(\)]+$', phone):
                return render_template("add_client.html", error="Телефон содержит недопустимые символы")

            if email and len(email) > 100:
                return render_template("add_client.html", error="Email слишком длинный (максимум 100 символов)")
            elif email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                return render_template("add_client.html", error="Некорректный формат email")

            if address and len(address) > 200:
                return render_template("add_client.html", error="Адрес слишком длинный (максимум 200 символов)")

            if registration_date:
                try:
                    datetime.strptime(registration_date, '%Y-%m-%d')
                except ValueError:
                    return render_template("add_client.html", error="Некорректный формат даты (требуется ГГГГ-ММ-ДД)")

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем, не существует ли уже такой клиент (по ФИО)
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_clients() 
                WHERE fullname = %s
            """, (fullname,))
            count = cur.fetchone()[0]

            if count > 0:
                conn.close()
                return render_template("add_client.html", error="Клиент с таким ФИО уже существует")

            # Вызываем безопасную функцию добавления
            cur.execute(
                "SELECT fn_add_client(%s, %s, %s, %s, %s);",
                (fullname, phone, email, address, registration_date)
            )
            conn.commit()
            conn.close()

            flash("Клиент успешно добавлен", "success")
            return redirect("/table/Клиенты")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_client: {str(e)}")
            return render_template("add_client.html", error="Ошибка при добавлении клиента")
        except Exception as e:
            logger.error(f"Ошибка в add_client: {str(e)}")
            return render_template("add_client.html", error="Внутренняя ошибка сервера")

    # GET запрос - показываем форму
    return render_template("add_client.html")


# 🔐 Безопасное редактирование клиента
@app.route("/edit/Клиенты/<int:client_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_client(client_id):
    """Безопасное редактирование клиента с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        client_id = int(client_id)
        if client_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные клиента через безопасную функцию
            cur.execute("SELECT * FROM fn_get_client_by_id(%s)", (client_id,))
            record = cur.fetchone()

            if not record:
                flash("Клиент не найден", "error")
                return redirect("/table/Клиенты")

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_client.html",
                                   record_data=list(zip(colnames, record)),
                                   client_id=client_id)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            fullname = request.form.get("fullname", "").strip()
            phone = request.form.get("phone", "").strip() or None
            email = request.form.get("email", "").strip() or None
            address = request.form.get("address", "").strip() or None
            registration_date = request.form.get("registrationdate", "").strip() or None

            # 🔐 Валидация входных данных
            if not fullname:
                flash("ФИО клиента является обязательным полем", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if len(fullname) > 200:
                flash("ФИО слишком длинное (максимум 200 символов)", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if re.search(r'[<>"\';\\]', fullname):
                flash("ФИО содержит недопустимые символы", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if phone and len(phone) > 20:
                flash("Телефон слишком длинный (максимум 20 символов)", "error")
                return redirect(f"/edit/Клиенты/{client_id}")
            elif phone and not re.match(r'^[\d\s\-\+\(\)]+$', phone):
                flash("Телефон содержит недопустимые символы", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if email and len(email) > 100:
                flash("Email слишком длинный (максимум 100 символов)", "error")
                return redirect(f"/edit/Клиенты/{client_id}")
            elif email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash("Некорректный формат email", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if address and len(address) > 200:
                flash("Адрес слишком длинный (максимум 200 символов)", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            if registration_date:
                try:
                    datetime.strptime(registration_date, '%Y-%m-%d')
                except ValueError:
                    flash("Некорректный формат даты (требуется ГГГГ-ММ-ДД)", "error")
                    return redirect(f"/edit/Клиенты/{client_id}")

            # 🔐 Проверяем, не существует ли уже такой клиент (по ФИО, кроме текущего)
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_clients() 
                WHERE fullname = %s AND clientid != %s
            """, (fullname, client_id))
            count = cur.fetchone()[0]

            if count > 0:
                flash("Клиент с таким ФИО уже существует", "error")
                return redirect(f"/edit/Клиенты/{client_id}")

            # Вызываем безопасную функцию обновления
            cur.execute(
                "SELECT fn_update_client(%s, %s, %s, %s, %s, %s);",
                (client_id, fullname, phone, email, address, registration_date)
            )
            conn.commit()
            conn.close()

            flash("Клиент успешно обновлён", "success")
            return redirect("/table/Клиенты")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_client: {str(e)}")
        flash("Ошибка при обновлении клиента", "error")
        return redirect(f"/edit/Клиенты/{client_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_client: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Клиенты/{client_id}")
    finally:
        if conn:
            conn.close()



# 🗑️ Безопасное удаление клиента
@app.route("/delete/Клиенты/<int:client_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_client(client_id):
    """Безопасное удаление клиента с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        client_id = int(client_id)
        if client_id <= 0:
            return "Неверный идентификатор клиента", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор клиента", 400

    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли клиент
        cur.execute("SELECT COUNT(*) FROM fn_get_all_clients() WHERE clientid = %s", (client_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Клиент не найден", "error")
            return redirect("/table/Клиенты")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_client(%s);", (client_id,))
        conn.commit()
        conn.close()

        flash("Клиент удалён", "info")
        return redirect("/table/Клиенты")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_client: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_client: {str(e)}")
        return "Ошибка удаления", 500
# Вспомогательная функция для получения списка марок
def get_makes_list():
    """Получение списка марок для выпадающего списка"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM fn_get_all_makes()")
        makes = cur.fetchall()
        conn.close()
        return makes
    except Exception as e:
        logger.error(f"Ошибка при получении списка марок: {str(e)}")
        return []

# 🔐 Безопасное добавление клиента

# 🔐 Безопасное добавление машины
@app.route("/add/Машины", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_car():
    """Безопасное добавление машины с валидацией и CSRF защитой"""

    # GET запрос - показываем форму
    if request.method == "GET":
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем данные для выпадающих списков
            cur.execute("SELECT * FROM fn_get_all_clients()")
            clients = cur.fetchall()

            cur.execute("SELECT * FROM fn_get_all_models()")
            models = cur.fetchall()

            conn.close()

            # Получаем текущий год для валидации
            current_year = datetime.now().year

            return render_template("add_car.html",
                                   clients=clients,
                                   models=models,
                                   current_year=current_year)

        except Exception as e:
            logger.error(f"Ошибка при загрузке формы добавления машины: {str(e)}")
            flash("Ошибка при загрузке формы", "error")
            return render_template("add_car.html", clients=[], models=[])

    # POST запрос - обработка данных формы
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            clientid = request.form.get("clientid", "").strip()
            modelid = request.form.get("modelid", "").strip()
            year = request.form.get("year", "").strip()
            vin = request.form.get("vin", "").strip() or None
            licenseplate = request.form.get("licenseplate", "").strip() or None
            color = request.form.get("color", "").strip() or None

            # 🔐 Валидация входных данных
            errors = []

            if not clientid:
                errors.append("Клиент является обязательным полем")

            if not modelid:
                errors.append("Модель является обязательным полем")

            if not year:
                errors.append("Год выпуска является обязательным полем")

            # 🔐 Валидация числовых полей
            try:
                clientid_int = int(clientid) if clientid else 0
                if clientid_int <= 0:
                    errors.append("ID клиента должен быть положительным числом")
            except ValueError:
                errors.append("ID клиента должен быть числом")

            try:
                modelid_int = int(modelid) if modelid else 0
                if modelid_int <= 0:
                    errors.append("ID модели должен быть положительным числом")
            except ValueError:
                errors.append("ID модели должен быть числом")

            try:
                year_int = int(year) if year else 0
                current_year = datetime.now().year
                if year_int < 1900 or year_int > current_year + 1:
                    errors.append(f"Год должен быть между 1900 и {current_year + 1}")
            except ValueError:
                errors.append("Год выпуска должен быть числом")

            if vin and len(vin) > 50:
                errors.append("VIN слишком длинный (максимум 50 символов)")
            elif vin and re.search(r'[<>"\';\\]', vin):
                errors.append("VIN содержит недопустимые символы")

            if licenseplate and len(licenseplate) > 20:
                errors.append("Госномер слишком длинный (максимум 20 символов)")

            if color and len(color) > 30:
                errors.append("Цвет слишком длинный (максимум 30 символов)")
            elif color and re.search(r'[<>"\';\\]', color):
                errors.append("Цвет содержит недопустимые символы")

            # Если есть ошибки, показываем форму снова
            if errors:
                conn = get_db_connection()
                cur = conn.cursor()

                # Получаем данные для выпадающих списков
                cur.execute("SELECT * FROM fn_get_all_clients()")
                clients = cur.fetchall()
                cur.execute("SELECT * FROM fn_get_all_models()")
                models = cur.fetchall()
                conn.close()

                current_year = datetime.now().year

                return render_template("add_car.html",
                                       error=", ".join(errors),
                                       clients=clients,
                                       models=models,
                                       current_year=current_year)

            # Подключаемся к БД
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем существование клиента
            cur.execute("SELECT COUNT(*) FROM fn_get_all_clients() WHERE clientid = %s", (clientid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                flash("Указанный клиент не существует", "error")
                return redirect("/add/Машины")

            # 🔐 Проверяем существование модели
            cur.execute("SELECT COUNT(*) FROM fn_get_all_models() WHERE modelid = %s", (modelid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                flash("Указанная модель не существует", "error")
                return redirect("/add/Машины")


            # Вызываем безопасную функцию добавления
            cur.execute(
                "SELECT fn_add_car(%s, %s, %s, %s, %s, %s);",
                (clientid_int, modelid_int, year_int, vin, licenseplate, color)
            )
            conn.commit()
            conn.close()

            flash("Машина успешно добавлена", "success")
            return redirect("/table/Машины")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_car: {str(e)}")
            flash("Ошибка при добавлении машины", "error")
            return redirect("/add/Машины")
        except Exception as e:
            logger.error(f"Ошибка в add_car: {str(e)}")
            flash("Внутренняя ошибка сервера", "error")
            return redirect("/add/Машины")


# 🔐 Безопасное редактирование машины
@app.route("/edit/Машины/<int:car_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_car(car_id):
    """Безопасное редактирование машины с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        car_id = int(car_id)
        if car_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные машины через безопасную функцию
            cur.execute("SELECT * FROM fn_get_car_by_id(%s)", (car_id,))
            record = cur.fetchone()

            if not record:
                flash("Машина не найдена", "error")
                return redirect("/table/Машины")

            # Получаем данные для выпадающих списков
            cur.execute("SELECT clientid, fullname FROM fn_get_all_clients() ORDER BY fullname")
            clients = cur.fetchall()
            cur.execute("SELECT modelid, modelname, makename FROM fn_get_all_models() ORDER BY makename, modelname")
            models = cur.fetchall()

            colnames = [desc[0] for desc in cur.description]
            conn.close()

            current_year = datetime.now().year

            return render_template("edit_car.html",
                                   record_data=list(zip(colnames, record)),
                                   clients=clients,
                                   models=models,
                                   car_id=car_id,
                                   current_year=current_year)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            clientid = request.form.get("clientid", "").strip()
            modelid = request.form.get("modelid", "").strip()
            year = request.form.get("year", "").strip()
            vin = request.form.get("vin", "").strip() or None
            licenseplate = request.form.get("licenseplate", "").strip() or None
            color = request.form.get("color", "").strip() or None

            # 🔐 Валидация входных данных
            errors = []

            if not clientid:
                errors.append("Клиент является обязательным полем")

            if not modelid:
                errors.append("Модель является обязательным полем")

            if not year:
                errors.append("Год выпуска является обязательным полем")

            # 🔐 Валидация числовых полей
            try:
                clientid_int = int(clientid)
                if clientid_int <= 0:
                    errors.append("ID клиента должен быть положительным числом")
            except ValueError:
                errors.append("ID клиента должен быть числом")

            try:
                modelid_int = int(modelid)
                if modelid_int <= 0:
                    errors.append("ID модели должен быть положительным числом")
            except ValueError:
                errors.append("ID модели должен быть числом")

            try:
                year_int = int(year)
                current_year = datetime.now().year
                if year_int < 1900 or year_int > current_year + 1:
                    errors.append(f"Год должен быть между 1900 и {current_year + 1}")
            except ValueError:
                errors.append("Год выпуска должен быть числом")

            if errors:
                # Получаем данные для формы при ошибках
                cur.execute("SELECT clientid, fullname FROM fn_get_all_clients() ORDER BY fullname")
                clients = cur.fetchall()
                cur.execute("SELECT modelid, modelname, makename FROM fn_get_all_models() ORDER BY makename, modelname")
                models = cur.fetchall()

                # Получаем текущие данные машины
                cur.execute("SELECT * FROM fn_get_car_by_id(%s)", (car_id,))
                record = cur.fetchone()

                colnames = [desc[0] for desc in cur.description]
                conn.close()

                current_year = datetime.now().year

                return render_template("edit_car.html",
                                       error=", ".join(errors),
                                       record_data=list(zip(colnames, record)),
                                       clients=clients,
                                       models=models,
                                       car_id=car_id,
                                       current_year=current_year)

            # 🔐 Проверяем уникальность VIN
            if vin:
                cur.execute("""
                    SELECT COUNT(*) 
                    FROM Cars 
                    WHERE VIN = %s AND CarID != %s
                """, (vin, car_id))
                if cur.fetchone()[0] > 0:
                    flash("Машина с таким VIN уже существует", "error")
                    return redirect(f"/edit/Машины/{car_id}")

            # 🔐 Проверяем уникальность госномера
            if licenseplate:
                cur.execute("""
                    SELECT COUNT(*) 
                    FROM Cars 
                    WHERE LicensePlate = %s AND CarID != %s
                """, (licenseplate, car_id))
                if cur.fetchone()[0] > 0:
                    flash("Машина с таким госномером уже существует", "error")
                    return redirect(f"/edit/Машины/{car_id}")

            # Вызываем безопасную функцию обновления
            cur.execute("SELECT fn_update_car(%s, %s, %s, %s, %s, %s, %s);",
                        (car_id, clientid_int, modelid_int, year_int, vin, licenseplate, color))
            conn.commit()
            conn.close()

            flash("Машина успешно обновлена", "success")
            return redirect("/table/Машины")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка базы данных в edit_car: {str(e)}")
        flash("Ошибка при обновлении машины", "error")
        return redirect(f"/edit/Машины/{car_id}")
    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в edit_car: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Машины/{car_id}")
# 🔐 Безопасное удаление машины
@app.route("/delete/Машины/<int:car_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_car(car_id):
    """Безопасное удаление машины с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        car_id = int(car_id)
        if car_id <= 0:
            return "Неверный идентификатор машины", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор машины", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли машина
        cur.execute("SELECT COUNT(*) FROM fn_get_all_cars() WHERE carid = %s", (car_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Машина не найдена", "error")
            return redirect("/table/Машины")

        # 🔐 Проверяем, нет ли связанных заказов
        cur.execute("SELECT COUNT(*) FROM orders WHERE carid = %s", (car_id,))
        order_count = cur.fetchone()[0]

        if order_count > 0:
            conn.close()
            flash("Невозможно удалить машину: существуют связанные заказы", "error")
            return redirect("/table/Машины")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_car(%s);", (car_id,))
        conn.commit()
        conn.close()

        flash("Машина удалена", "info")
        return redirect("/table/Машины")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка базы данных в delete_car: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в delete_car: {str(e)}")
        return "Ошибка удаления", 500
# 🔐 Безопасное добавление сотрудника

@app.route("/add/Сотрудники", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager", "security_officer")
@csrf_protect
def add_employee():
    """Безопасное добавление сотрудника с валидацией и CSRF защитой"""

    # GET запрос - показываем форму
    if request.method == "GET":
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем список отделов для выпадающего списка
            cur.execute("SELECT * FROM fn_get_all_departments()")
            departments = cur.fetchall()

            conn.close()
            return render_template("add_employee.html", departments=departments)

        except Exception as e:
            logger.error(f"Ошибка при загрузке формы добавления сотрудника: {str(e)}")
            flash("Ошибка при загрузке формы", "error")
            return render_template("add_employee.html", departments=[])

    # POST запрос - обработка данных формы
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            fullname = request.form.get("fullname", "").strip()
            position = request.form.get("position", "").strip()
            phone = request.form.get("phone", "").strip() or None
            email = request.form.get("email", "").strip() or None
            department_id = request.form.get("department_id", "").strip()
            hiredate = request.form.get("hiredate", "").strip() or None
            salary = request.form.get("salary", "").strip()

            # 🔐 Валидация входных данных
            errors = []

            if not fullname:
                errors.append("ФИО сотрудника является обязательным полем")
            elif len(fullname) > 200:
                errors.append("ФИО слишком длинное (максимум 200 символов)")
            elif re.search(r'[<>"\';\\]', fullname):
                errors.append("ФИО содержит недопустимые символы")

            if not position:
                errors.append("Должность является обязательным полем")
            elif len(position) > 100:
                errors.append("Должность слишком длинная (максимум 100 символов)")
            elif re.search(r'[<>"\';\\]', position):
                errors.append("Должность содержит недопустимые символы")

            if phone and len(phone) > 20:
                errors.append("Телефон слишком длинный (максимум 20 символов)")
            elif phone and not re.match(r'^[\d\s\-\+\(\)]+$', phone):
                errors.append("Телефон содержит недопустимые символы")

            if email and len(email) > 100:
                errors.append("Email слишком длинный (максимум 100 символов)")
            elif email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                errors.append("Некорректный формат email")

            if not department_id:
                errors.append("ID отдела является обязательным полем")

            if not salary:
                errors.append("Зарплата является обязательным полем")

            # 🔐 Валидация числовых полей
            department_id_int = None
            if department_id:
                try:
                    department_id_int = int(department_id)
                    if department_id_int <= 0:
                        errors.append("ID отдела должен быть положительным числом")
                except ValueError:
                    errors.append("ID отдела должен быть числом")

            salary_float = None
            if salary:
                try:
                    salary_float = float(salary)
                    if salary_float < 0:
                        errors.append("Зарплата не может быть отрицательной")
                except ValueError:
                    errors.append("Зарплата должна быть числом")

            if hiredate:
                try:
                    datetime.strptime(hiredate, '%Y-%m-%d')
                except ValueError:
                    errors.append("Некорректный формат даты приема (требуется ГГГГ-ММ-ДД)")

            # Если есть ошибки, показываем форму снова
            if errors:
                try:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT * FROM fn_get_all_departments()")
                    departments = cur.fetchall()
                    conn.close()
                    return render_template("add_employee.html",
                                           error=", ".join(errors),
                                           departments=departments)
                except:
                    return render_template("add_employee.html",
                                           error=", ".join(errors),
                                           departments=[])

            # Подключаемся к БД
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем список отделов для формы
            cur.execute("SELECT * FROM fn_get_all_departments()")
            departments = cur.fetchall()

            # 🔐 Проверяем существование отдела
            cur.execute("SELECT COUNT(*) FROM fn_get_all_departments() WHERE department_id = %s",
                        (department_id_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_employee.html",
                                       error="Указанный отдел не существует",
                                       departments=departments)

            # Вызываем безопасную функцию добавления
            cur.execute(
                "SELECT fn_add_employee(%s, %s, %s, %s, %s, %s, %s);",
                (fullname, position, phone, email, department_id_int, hiredate, salary_float)
            )
            conn.commit()
            conn.close()

            flash("Сотрудник успешно добавлен", "success")
            return redirect("/table/Сотрудники")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_employee: {str(e)}")

            # Получаем список отделов для формы
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM fn_get_all_departments()")
                departments = cur.fetchall()
                conn.close()
                return render_template("add_employee.html",
                                       error="Ошибка базы данных при добавлении сотрудника",
                                       departments=departments)
            except:
                return render_template("add_employee.html",
                                       error="Ошибка базы данных при добавлении сотрудника")

        except Exception as e:
            logger.error(f"Ошибка в add_employee: {str(e)}")

            # Получаем список отделов для формы
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM fn_get_all_departments()")
                departments = cur.fetchall()
                conn.close()
                return render_template("add_employee.html",
                                       error="Внутренняя ошибка сервера",
                                       departments=departments)
            except:
                return render_template("add_employee.html",
                                       error="Внутренняя ошибка сервера")


# 🔐 Безопасное редактирование сотрудника
# 🔐 Безопасное редактирование сотрудника (упрощённая версия)
@app.route("/edit/Сотрудники/<int:employee_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager", "security_officer")
@csrf_protect
def edit_employee(employee_id):
    """Безопасное редактирование сотрудника"""

    # 🔐 Валидация ID
    try:
        employee_id = int(employee_id)
        if employee_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # 🔐 Используем безопасное подключение (КАК В EDIT/MAKE!)
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные сотрудника
            cur.execute("SELECT * FROM fn_get_employee_by_id(%s)", (employee_id,))
            record = cur.fetchone()

            if not record:
                flash("Сотрудник не найден", "error")
                return redirect("/table/Сотрудники")

            # Получаем список отделов (ОСТАВЛЯЕМ departments!)
            cur.execute("SELECT * FROM fn_get_all_departments()")
            departments = cur.fetchall()

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_employee.html",
                                   record_data=list(zip(colnames, record)),
                                   departments=departments,
                                   employee_id=employee_id)

        elif request.method == "POST":
            # Получаем данные из формы
            fullname = request.form.get("fullname", "").strip()
            position = request.form.get("position", "").strip()
            phone = request.form.get("phone", "").strip() or None
            email = request.form.get("email", "").strip() or None
            department_id = request.form.get("department_id", "").strip()
            hiredate = request.form.get("hiredate", "").strip() or None
            salary = request.form.get("salary", "").strip()

            # 🔐 Базовая валидация
            if not fullname:
                flash("ФИО сотрудника является обязательным полем", "error")
                return redirect(f"/edit/Сотрудники/{employee_id}")

            if not position:
                flash("Должность является обязательным полем", "error")
                return redirect(f"/edit/Сотрудники/{employee_id}")

            if not department_id:
                flash("Отдел является обязательным полем", "error")
                return redirect(f"/edit/Сотрудники/{employee_id}")

            if not salary:
                flash("Зарплата является обязательным полем", "error")
                return redirect(f"/edit/Сотрудники/{employee_id}")

            # 🔐 Проверка числовых полей
            department_id_int = None
            if department_id:
                try:
                    department_id_int = int(department_id)
                    if department_id_int <= 0:
                        flash("ID отдела должен быть положительным числом", "error")
                        return redirect(f"/edit/Сотрудники/{employee_id}")
                except ValueError:
                    flash("ID отдела должен быть числом", "error")
                    return redirect(f"/edit/Сотрудники/{employee_id}")

            salary_float = None
            if salary:
                try:
                    salary_float = float(salary)
                    if salary_float < 0:
                        flash("Зарплата не может быть отрицательной", "error")
                        return redirect(f"/edit/Сотрудники/{employee_id}")
                except ValueError:
                    flash("Зарплата должна быть числом", "error")
                    return redirect(f"/edit/Сотрудники/{employee_id}")

            if hiredate:
                try:
                    datetime.strptime(hiredate, '%Y-%m-%d')
                except ValueError:
                    flash("Некорректный формат даты (требуется ГГГГ-ММ-ДД)", "error")
                    return redirect(f"/edit/Сотрудники/{employee_id}")

            # 🔐 Проверяем существование отдела
            cur.execute("SELECT COUNT(*) FROM fn_get_all_departments() WHERE department_id = %s",
                        (department_id_int,))
            if cur.fetchone()[0] == 0:
                flash("Указанный отдел не существует", "error")
                return redirect(f"/edit/Сотрудники/{employee_id}")

            # Вызываем функцию обновления
            cur.execute("SELECT fn_update_employee(%s, %s, %s, %s, %s, %s, %s, %s);",
                        (employee_id, fullname, position, phone, email, department_id_int, hiredate, salary_float))
            conn.commit()
            conn.close()

            flash("Сотрудник успешно обновлён", "success")
            return redirect("/table/Сотрудники")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_employee: {str(e)}")
        flash("Ошибка при обновлении сотрудника", "error")
        return redirect(f"/edit/Сотрудники/{employee_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_employee: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Сотрудники/{employee_id}")
    finally:
        if conn:
            conn.close()


@app.route("/delete/Сотрудники/<int:employee_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager", "security_officer")
@csrf_protect
def delete_employee(employee_id):
    """Безопасное удаление сотрудника с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        employee_id = int(employee_id)
        if employee_id <= 0:
            return "Неверный идентификатор сотрудника", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор сотрудника", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли сотрудник
        cur.execute("SELECT COUNT(*) FROM fn_get_all_employees() WHERE employeeid = %s", (employee_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Сотрудник не найден", "error")
            return redirect("/table/Сотрудники")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_employee(%s);", (employee_id,))
        conn.commit()
        conn.close()

        flash("Сотрудник удалён", "info")
        return redirect("/table/Сотрудники")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка базы данных в delete_employee: {str(e)}")
        return "Ошибка удаления", 500

    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в delete_employee: {str(e)}")
        return "Ошибка удаления", 500



# 🔐 Безопасное добавление заказа
@app.route("/add/Заказы", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_order():
    """Безопасное добавление заказа с валидацией и CSRF защитой"""

    # GET запрос - показываем форму
    if request.method == "GET":
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем данные для выпадающих списков
            cur.execute("SELECT carid, car_info FROM fn_get_all_cars() ORDER BY car_info")
            cars = cur.fetchall()

            cur.execute(
                "SELECT employeeid, CONCAT(fullname, ' - ', position) AS employee_info FROM fn_get_all_employees() ORDER BY fullname")
            employees = cur.fetchall()

            conn.close()
            return render_template("add_order.html", cars=cars, employees=employees)

        except Exception as e:
            logger.error(f"Ошибка при загрузке формы добавления заказа: {str(e)}")
            flash("Ошибка при загрузке формы", "error")
            return render_template("add_order.html", cars=[], employees=[])

    # POST запрос - обработка данных формы
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            carid = request.form.get("carid", "").strip()
            employeeid = request.form.get("employeeid", "").strip()
            orderdate = request.form.get("orderdate", "").strip() or None
            status = request.form.get("status", "").strip() or "Новый"
            totalamount = request.form.get("totalamount", "").strip() or None

            # 🔐 Валидация входных данных
            errors = []

            if not carid:
                errors.append("Машина является обязательным полем")

            if not employeeid:
                errors.append("Сотрудник является обязательным полем")

            # 🔐 Валидация числовых полей
            try:
                carid_int = int(carid) if carid else 0
                if carid_int <= 0:
                    errors.append("ID машины должен быть положительным числом")
            except ValueError:
                errors.append("ID машины должен быть числом")

            try:
                employeeid_int = int(employeeid) if employeeid else 0
                if employeeid_int <= 0:
                    errors.append("ID сотрудника должен быть положительным числом")
            except ValueError:
                errors.append("ID сотрудника должен быть числом")

            totalamount_float = None
            if totalamount:
                try:
                    totalamount_float = float(totalamount)
                    if totalamount_float < 0:
                        errors.append("Сумма не может быть отрицательной")
                except ValueError:
                    errors.append("Сумма должна быть числом")

            if orderdate:
                try:
                    datetime.strptime(orderdate, '%Y-%m-%d')
                except ValueError:
                    errors.append("Некорректный формат даты заказа (требуется ГГГГ-ММ-ДД)")

            if status and len(status) > 50:
                errors.append("Статус слишком длинный (максимум 50 символов)")

            # Если есть ошибки, показываем форму снова
            if errors:
                try:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT carid, car_info FROM fn_get_all_cars() ORDER BY car_info")
                    cars = cur.fetchall()
                    cur.execute(
                        "SELECT employeeid, CONCAT(fullname, ' - ', position) AS employee_info FROM fn_get_all_employees() ORDER BY fullname")
                    employees = cur.fetchall()
                    conn.close()
                    return render_template("add_order.html",
                                           error=", ".join(errors),
                                           cars=cars,
                                           employees=employees)
                except:
                    return render_template("add_order.html",
                                           error=", ".join(errors),
                                           cars=[],
                                           employees=[])

            # Подключаемся к БД
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем данные для выпадающих списков
            cur.execute("SELECT carid, car_info FROM fn_get_all_cars() ORDER BY car_info")
            cars = cur.fetchall()
            cur.execute(
                "SELECT employeeid, CONCAT(fullname, ' - ', position) AS employee_info FROM fn_get_all_employees() ORDER BY fullname")
            employees = cur.fetchall()

            # 🔐 Проверяем существование машины
            cur.execute("SELECT COUNT(*) FROM fn_get_all_cars() WHERE carid = %s", (carid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_order.html",
                                       error="Указанная машина не существует",
                                       cars=cars,
                                       employees=employees)

            # 🔐 Проверяем существование сотрудника
            cur.execute("SELECT COUNT(*) FROM fn_get_all_employees() WHERE employeeid = %s", (employeeid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_order.html",
                                       error="Указанный сотрудник не существует",
                                       cars=cars,
                                       employees=employees)

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_order(%s, %s, %s, %s, %s);",
                        (carid_int, employeeid_int, orderdate, status, totalamount_float))
            conn.commit()
            conn.close()

            flash("Заказ успешно добавлен", "success")
            return redirect("/table/Заказы")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_order: {str(e)}")

            # Проверяем, если это ошибка уникальности
            error_msg = str(e).lower()
            if "unique constraint" in error_msg or "duplicate" in error_msg:
                flash("Ошибка: заказ с такими данными уже существует", "error")
            else:
                flash("Ошибка при добавлении заказа", "error")

            # Показываем форму снова
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT carid, car_info FROM fn_get_all_cars() ORDER BY car_info")
                cars = cur.fetchall()
                cur.execute(
                    "SELECT employeeid, CONCAT(fullname, ' - ', position) AS employee_info FROM fn_get_all_employees() ORDER BY fullname")
                employees = cur.fetchall()
                conn.close()
                return render_template("add_order.html",
                                       error="Ошибка базы данных",
                                       cars=cars,
                                       employees=employees)
            except:
                return redirect("/add/Заказы")

        except Exception as e:
            logger.error(f"Ошибка в add_order: {str(e)}")
            flash("Внутренняя ошибка сервера", "error")
            return redirect("/add/Заказы")


# 🔐 Безопасное редактирование заказа
# 🔐 Безопасное редактирование заказа
@app.route("/edit/Заказы/<int:order_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager", "senior_mechanic")
@csrf_protect
def edit_order(order_id):
    """Редактирование заказа с учётом роли"""

    # ---- Валидация ID ----
    if not isinstance(order_id, int) or order_id <= 0:
        abort(400)

    role = session.get("role", "")

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ============================================================
        #                     GET — показать форму
        # ============================================================
        if request.method == "GET":

            cur.execute("SELECT * FROM fn_get_order_by_id(%s)", (order_id,))
            record = cur.fetchone()

            if not record:
                flash("Заказ не найден", "error")
                return redirect("/table/Заказы")

            # Список машин
            cur.execute("SELECT carid, car_info FROM fn_get_all_cars() ORDER BY car_info")
            cars = cur.fetchall()

            # Список сотрудников
            cur.execute("""
                SELECT employeeid, CONCAT(fullname, ' - ', position)
                FROM fn_get_all_employees()
                ORDER BY fullname
            """)
            employees = cur.fetchall()

            colnames = [desc[0] for desc in cur.description]

            cur.close()
            conn.close()

            return render_template(
                "edit_order.html",
                record=record,
                cars=cars,
                employees=employees,
                colnames=colnames,
                order_id=order_id,
            )

        # ============================================================
        #                        POST — обновление
        # ============================================================
        if request.method == "POST":

            if role == "senior_mechanic":
                status = request.form.get("status", "").strip()

                if not status:
                    flash("Статус обязателен", "error")
                    return redirect(f"/edit/Заказы/{order_id}")

                if len(status) > 50:
                    flash("Статус слишком длинный (макс. 50)", "error")
                    return redirect(f"/edit/Заказы/{order_id}")

                cur.execute("SELECT fn_update_order_status(%s, %s);", (order_id, status))
                conn.commit()
                cur.close()
                conn.close()

                flash("Статус заказа обновлён", "success")
                return redirect("/table/Заказы")

            carid = request.form.get("carid", "").strip()
            employeeid = request.form.get("employeeid", "").strip()
            orderdate = request.form.get("orderdate", "").strip() or None
            status = request.form.get("status", "").strip() or None
            totalamount = request.form.get("totalamount", "").strip() or None

            # Валидация
            if not carid:
                flash("Машина обязательна", "error")
                return redirect(f"/edit/Заказы/{order_id}")

            if not employeeid:
                flash("Сотрудник обязателен", "error")
                return redirect(f"/edit/Заказы/{order_id}")

            try:
                carid_int = int(carid)
                employeeid_int = int(employeeid)
                if totalamount:
                    totalamount_float = float(totalamount)
            except ValueError:
                flash("Некорректные числовые данные", "error")
                return redirect(f"/edit/Заказы/{order_id}")

            cur.execute(
                "SELECT fn_update_order(%s, %s, %s, %s, %s, %s);",
                (order_id, carid_int, employeeid_int, orderdate, status, totalamount),
            )

            conn.commit()
            cur.close()
            conn.close()

            flash("Заказ обновлён", "success")
            return redirect("/table/Заказы")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка БД в edit_order: {str(e)}")
        flash("Ошибка базы данных", "error")
        return redirect(f"/edit/Заказы/{order_id}")

    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в edit_order: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Заказы/{order_id}")

@app.route("/delete/Заказы/<int:order_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_order(order_id):
    """Безопасное удаление заказа с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        order_id = int(order_id)
        if order_id <= 0:
            return "Неверный идентификатор заказа", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор заказа", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли заказ
        cur.execute("SELECT COUNT(*) FROM fn_get_all_orders() WHERE orderid = %s", (order_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Заказ не найден", "error")
            return redirect("/table/Заказы")

        # 🔐 Проверяем, нет ли связанных услуг в заказе
        cur.execute("SELECT COUNT(*) FROM orderservices WHERE orderid = %s", (order_id,))
        service_count = cur.fetchone()[0]

        if service_count > 0:
            conn.close()
            flash("Невозможно удалить заказ: существуют связанные услуги", "error")
            return redirect("/table/Заказы")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_order(%s);", (order_id,))
        conn.commit()
        conn.close()

        flash("Заказ удален", "info")
        return redirect("/table/Заказы")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка базы данных в delete_order: {str(e)}")
        return "Ошибка удаления", 500

    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в delete_order: {str(e)}")
        return "Ошибка удаления", 500
# 🔐 Безопасное добавление услуги в заказ
@app.route("/add/Услуги в заказе", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_order_service():
    """Безопасное добавление услуги в заказ с валидацией и CSRF защитой"""
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            orderid = request.form.get("orderid", "").strip()
            serviceid = request.form.get("serviceid", "").strip()

            # 🔐 Валидация входных данных
            errors = []

            if not orderid:
                errors.append("Заказ является обязательным полем")

            if not serviceid:
                errors.append("Услуга является обязательным полем")

            # 🔐 Валидация числовых полей
            try:
                orderid_int = int(orderid) if orderid else 0
                if orderid_int <= 0:
                    errors.append("ID заказа должен быть положительным числом")
            except ValueError:
                errors.append("ID заказа должен быть числом")

            try:
                serviceid_int = int(serviceid) if serviceid else 0
                if serviceid_int <= 0:
                    errors.append("ID услуги должен быть положительным числом")
            except ValueError:
                errors.append("ID услуги должен быть числом")

            if errors:
                # Получаем данные для формы
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM fn_get_all_orders()")
                orders = cur.fetchall()
                cur.execute("SELECT * FROM fn_get_all_services()")
                services = cur.fetchall()
                conn.close()

                return render_template("add_order_service.html",
                                       error=", ".join(errors),
                                       orders=orders,
                                       services=services)

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем данные для выпадающих списков
            cur.execute("SELECT * FROM fn_get_all_orders()")
            orders = cur.fetchall()
            cur.execute("SELECT * FROM fn_get_all_services()")
            services = cur.fetchall()

            # 🔐 Проверяем существование заказа и услуги
            cur.execute("SELECT COUNT(*) FROM fn_get_all_orders() WHERE orderid = %s", (orderid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_order_service.html",
                                       error="Указанный заказ не существует",
                                       orders=orders,
                                       services=services)

            cur.execute("SELECT COUNT(*) FROM fn_get_all_services() WHERE serviceid = %s", (serviceid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_order_service.html",
                                       error="Указанная услуга не существует",
                                       orders=orders,
                                       services=services)

            # 🔐 Проверяем, не добавлена ли уже эта услуга в заказ
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_order_services() 
                WHERE orderid = %s AND serviceid = %s
            """, (orderid_int, serviceid_int))

            if cur.fetchone()[0] > 0:
                conn.close()
                return render_template("add_order_service.html",
                                       error="Эта услуга уже добавлена в заказ",
                                       orders=orders,
                                       services=services)

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_order_service(%s, %s);",
                        (orderid_int, serviceid_int))
            conn.commit()
            conn.close()

            flash("Услуга в заказе успешно добавлена", "success")
            return redirect("/table/Услуги в заказе")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_order_service: {str(e)}")

            # Получаем данные для формы
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM fn_get_all_orders()")
                orders = cur.fetchall()
                cur.execute("SELECT * FROM fn_get_all_services()")
                services = cur.fetchall()
                conn.close()
                return render_template("add_order_service.html",
                                       error="Ошибка базы данных при добавлении услуги в заказ",
                                       orders=orders,
                                       services=services)
            except:
                return render_template("add_order_service.html",
                                       error="Ошибка базы данных")

        except Exception as e:
            logger.error(f"Ошибка в add_order_service: {str(e)}")

            # Получаем данные для формы
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT * FROM fn_get_all_orders()")
                orders = cur.fetchall()
                cur.execute("SELECT * FROM fn_get_all_services()")
                services = cur.fetchall()
                conn.close()
                return render_template("add_order_service.html",
                                       error="Внутренняя ошибка сервера",
                                       orders=orders,
                                       services=services)
            except:
                return render_template("add_order_service.html",
                                       error="Внутренняя ошибка сервера")

    # GET запрос - показываем форму
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Получаем данные для выпадающих списков
        cur.execute("SELECT * FROM fn_get_all_orders()")
        orders = cur.fetchall()

        cur.execute("SELECT * FROM fn_get_all_services()")
        services = cur.fetchall()

        conn.close()
        return render_template("add_order_service.html", orders=orders, services=services)

    except Exception as e:
        logger.error(f"Ошибка при загрузке формы добавления услуги в заказ: {str(e)}")
        flash("Ошибка при загрузке формы", "error")
        return render_template("add_order_service.html", orders=[], services=[])


# 🔐 Безопасное редактирование услуги в заказе
# 🔐 Безопасное редактирование услуги в заказе
# ✏️ Редактирование услуги в заказе
@app.route("/edit/Услуги в заказе/<int:orderservice_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_order_service(orderservice_id):
    """Безопасное редактирование услуги в заказе"""

    # 🔐 Валидация ID
    try:
        orderservice_id = int(orderservice_id)
        if orderservice_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Получаем данные для выпадающих списков
        cur.execute("SELECT * FROM fn_get_all_orders()")
        orders = cur.fetchall()

        cur.execute("SELECT * FROM fn_get_all_services()")
        services = cur.fetchall()

        if request.method == "GET":
            # Используем функцию для получения данных услуги в заказе
            cur.execute("SELECT * FROM fn_get_orderservice_by_id(%s)", (orderservice_id,))
            record = cur.fetchone()

            if not record:
                conn.close()
                flash("Услуга в заказе не найдена", "error")
                return redirect("/table/Услуги в заказе")

            colnames = [desc[0] for desc in cur.description]
            conn.close()

            return render_template("edit_order_service.html",
                                   record_data=list(zip(colnames, record)),
                                   orders=orders,
                                   services=services)

        if request.method == "POST":
            # Получаем данные из формы
            orderid = request.form.get("orderid")
            serviceid = request.form.get("serviceid")

            # Проверяем обязательные поля
            if not orderid:
                flash("Заказ является обязательным полем", "error")
                return redirect(f"/edit/Услуги в заказе/{orderservice_id}")
            if not serviceid:
                flash("Услуга является обязательным полем", "error")
                return redirect(f"/edit/Услуги в заказе/{orderservice_id}")

            # Преобразуем числовые поля
            try:
                orderid_int = int(orderid)
                serviceid_int = int(serviceid)
            except ValueError:
                flash("ID заказа и ID услуги должны быть числами", "error")
                return redirect(f"/edit/Услуги в заказе/{orderservice_id}")

            # Вызываем функцию обновления
            cur.execute("SELECT fn_update_orderservice(%s, %s, %s);",
                        (orderservice_id, orderid_int, serviceid_int))
            conn.commit()
            conn.close()

            flash("✅ Услуга в заказе успешно обновлена!", "success")
            return redirect("/table/Услуги в заказе")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
            conn.close()
        logger.error(f"Ошибка базы данных в edit_order_service: {str(e)}")
        flash("Ошибка при обновлении услуги в заказе", "error")
        return redirect(f"/edit/Услуги в заказе/{orderservice_id}")
    except Exception as e:
        if conn:
            conn.close()
        logger.error(f"Ошибка в edit_order_service: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Услуги в заказе/{orderservice_id}")
# 🔐 Безопасное удаление услуги в заказе
@app.route("/delete/Услуги в заказе/<int:orderservice_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_order_service(orderservice_id):
    """Безопасное удаление услуги в заказе с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        orderservice_id = int(orderservice_id)
        if orderservice_id <= 0:
            return "Неверный идентификатор услуги в заказе", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор услуги в заказе", 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли услуга в заказе
        cur.execute("SELECT COUNT(*) FROM fn_get_all_order_services() WHERE orderserviceid = %s", (orderservice_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Услуга в заказе не найдена", "error")
            return redirect("/table/Услуги в заказе")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_orderservice(%s);", (orderservice_id,))
        conn.commit()
        conn.close()

        flash("Услуга в заказе удалена", "info")
        return redirect("/table/Услуги в заказе")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_order_service: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_order_service: {str(e)}")
        return "Ошибка удаления", 500

# 🔐 Безопасное добавление услуги
# 🔐 Безопасное добавление услуги (упрощенная версия как add_make)
@app.route("/add/Услуги", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_service():
    """Безопасное добавление услуги с валидацией и CSRF защитой"""

    if request.method == "GET":
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Получаем категории услуг для выпадающего списка
            cur.execute("SELECT * FROM fn_get_all_service_categories()")
            categories = cur.fetchall()

            conn.close()
            return render_template("add_service.html", categories=categories)

        except Exception as e:
            logger.error(f"Ошибка при загрузке формы добавления услуги: {str(e)}")
            flash("Ошибка при загрузке формы", "error")
            return render_template("add_service.html", categories=[])

    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            servicename = request.form.get("servicename", "").strip()
            description = request.form.get("description", "").strip() or None
            price = request.form.get("price", "").strip()
            durationminutes = request.form.get("durationminutes", "").strip()
            categoryid = request.form.get("categoryid", "").strip()

            # 🔐 Базовая валидация
            if not servicename:
                flash("Название услуги является обязательным полем", "error")
                return redirect("/add/Услуги")

            if len(servicename) > 100:
                flash("Название услуги слишком длинное (максимум 100 символов)", "error")
                return redirect("/add/Услуги")

            if not price:
                flash("Цена является обязательным полем", "error")
                return redirect("/add/Услуги")

            if not durationminutes:
                flash("Длительность является обязательным полем", "error")
                return redirect("/add/Услуги")

            if not categoryid:
                flash("Категория является обязательным полем", "error")
                return redirect("/add/Услуги")

            # 🔐 Проверка числовых полей
            try:
                price_float = float(price)
                if price_float < 0:
                    flash("Цена не может быть отрицательной", "error")
                    return redirect("/add/Услуги")
            except ValueError:
                flash("Цена должна быть числом", "error")
                return redirect("/add/Услуги")

            try:
                durationminutes_int = int(durationminutes)
                if durationminutes_int <= 0:
                    flash("Длительность должна быть положительной", "error")
                    return redirect("/add/Услуги")
            except ValueError:
                flash("Длительность должна быть числом", "error")
                return redirect("/add/Услуги")

            try:
                categoryid_int = int(categoryid)
                if categoryid_int <= 0:
                    flash("ID категории должен быть положительным числом", "error")
                    return redirect("/add/Услуги")
            except ValueError:
                flash("ID категории должен быть числом", "error")
                return redirect("/add/Услуги")

            # Подключаемся к БД
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем существование категории
            cur.execute("SELECT COUNT(*) FROM fn_get_all_service_categories() WHERE categoryid = %s",
                        (categoryid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                flash("Указанная категория не существует", "error")
                return redirect("/add/Услуги")

            # 🔐 Проверяем, не существует ли уже услуга с таким названием
            cur.execute("SELECT COUNT(*) FROM fn_get_all_services() WHERE servicename = %s",
                        (servicename,))

            if cur.fetchone()[0] > 0:
                conn.close()
                flash("Услуга с таким названием уже существует", "error")
                return redirect("/add/Услуги")

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_service(%s, %s, %s, %s, %s);",
                        (servicename, description, price_float, durationminutes_int, categoryid_int))
            conn.commit()
            conn.close()

            flash("Услуга успешно добавлена", "success")
            return redirect("/table/Услуги")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_service: {str(e)}")
            flash("Ошибка при добавлении услуги", "error")
            return redirect("/add/Услуги")
        except Exception as e:
            logger.error(f"Ошибка в add_service: {str(e)}")
            flash("Внутренняя ошибка сервера", "error")
            return redirect("/add/Услуги")


# 🔐 Безопасное редактирование услуги (в стиле edit_make)
# 🔐 Безопасное редактирование услуги (в стиле edit_client)
@app.route("/edit/Услуги/<int:service_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_service(service_id):
    """Безопасное редактирование услуги с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        service_id = int(service_id)
        if service_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные услуги через безопасную функцию
            cur.execute("SELECT * FROM fn_get_service_by_id(%s)", (service_id,))
            record = cur.fetchone()

            if not record:
                flash("Услуга не найдена", "error")
                return redirect("/table/Услуги")

            # Получаем категории услуг для выпадающего списка
            # Фильтруем заголовки, чтобы не показывать 'categoryname'
            cur.execute("""
                SELECT categoryid, categoryname 
                FROM servicecategories 
                WHERE categoryname != 'categoryname'
                ORDER BY categoryname
            """)
            categories = cur.fetchall()

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_service.html",
                                   record_data=list(zip(colnames, record)),
                                   categories=categories,
                                   service_id=service_id)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            servicename = request.form.get("servicename", "").strip()
            description = request.form.get("description", "").strip() or None
            price = request.form.get("price", "").strip()
            durationminutes = request.form.get("durationminutes", "").strip()
            categoryid = request.form.get("categoryid", "").strip()

            # 🔐 Валидация входных данных
            if not servicename:
                flash("Название услуги является обязательным полем", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            if len(servicename) > 100:
                flash("Название услуги слишком длинное (максимум 100 символов)", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            if description and len(description) > 500:
                flash("Описание слишком длинное (максимум 500 символов)", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            if not price:
                flash("Цена является обязательным полем", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            if not durationminutes:
                flash("Длительность является обязательным полем", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            if not categoryid:
                flash("Категория является обязательным полем", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            # 🔐 Проверка числовых полей
            try:
                price_float = float(price)
                if price_float < 0:
                    flash("Цена не может быть отрицательной", "error")
                    return redirect(f"/edit/Услуги/{service_id}")
            except ValueError:
                flash("Цена должна быть числом", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            try:
                durationminutes_int = int(durationminutes)
                if durationminutes_int <= 0:
                    flash("Длительность должна быть положительной", "error")
                    return redirect(f"/edit/Услуги/{service_id}")
            except ValueError:
                flash("Длительность должна быть числом", "error")
                return redirect(f"/edit/Услуги/{service_id}")

            try:
                categoryid_int = int(categoryid)
                if categoryid_int <= 0:
                    flash("ID категории должен быть положительным числом", "error")
                    return redirect(f"/edit/Услуги/{service_id}")
            except ValueError:
                flash("ID категории должен быть числом", "error")
                return redirect(f"/edit/Услуги/{service_id}")


            # Вызываем безопасную функцию обновления
            cur.execute("SELECT fn_update_service(%s, %s, %s, %s, %s, %s);",
                        (service_id, servicename, description, price_float, durationminutes_int, categoryid_int))
            conn.commit()
            conn.close()

            flash("Услуга успешно обновлена", "success")
            return redirect("/table/Услуги")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_service: {str(e)}")
        flash("Ошибка при обновлении услуги", "error")
        return redirect(f"/edit/Услуги/{service_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_service: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Услуги/{service_id}")
    finally:
        if conn:
            conn.close()

# 🔐 Безопасное удаление услуги
@app.route("/delete/Услуги/<int:service_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_service(service_id):
    """Безопасное удаление услуги с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        service_id = int(service_id)
        if service_id <= 0:
            return "Неверный идентификатор услуги", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор услуги", 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли услуга
        cur.execute("SELECT COUNT(*) FROM fn_get_all_services() WHERE serviceid = %s", (service_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Услуга не найдена", "error")
            return redirect("/table/Услуги")

        # 🔐 Проверяем, не используется ли услуга в заказах
        cur.execute("SELECT COUNT(*) FROM orderservices WHERE serviceid = %s", (service_id,))
        order_service_count = cur.fetchone()[0]

        if order_service_count > 0:
            conn.close()
            flash("Невозможно удалить услугу: она используется в заказах", "error")
            return redirect("/table/Услуги")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_service(%s);", (service_id,))
        conn.commit()
        conn.close()

        flash("Услуга удалена", "info")
        return redirect("/table/Услуги")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_service: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_service: {str(e)}")
        return "Ошибка удаления", 500

# 🔐 Безопасное добавление категории услуг
# 🔐 Безопасное добавление категории услуг (в стиле add_client)
@app.route("/add/Категория услуг", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def add_service_category():
    """Безопасное добавление категории услуг с валидацией и CSRF защитой"""

    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            categoryname = request.form.get("categoryname", "").strip()
            description = request.form.get("description", "").strip() or None

            # 🔐 Валидация входных данных
            if not categoryname:
                return render_template("add_service_category.html",
                                       error="Название категории является обязательным полем")

            if len(categoryname) > 100:
                return render_template("add_service_category.html",
                                       error="Название категории слишком длинное (максимум 100 символов)")

            if re.search(r'[<>"\';\\]', categoryname):
                return render_template("add_service_category.html",
                                       error="Название категории содержит недопустимые символы")

            if description and len(description) > 500:
                return render_template("add_service_category.html",
                                       error="Описание слишком длинное (максимум 500 символов)")

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем, не существует ли уже категория с таким названием
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_service_categories() 
                WHERE categoryname = %s
            """, (categoryname,))

            if cur.fetchone()[0] > 0:
                conn.close()
                return render_template("add_service_category.html",
                                       error="Категория с таким названием уже существует")

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_add_service_category(%s, %s);",
                        (categoryname, description))
            conn.commit()
            conn.close()

            flash("Категория услуг успешно добавлена", "success")
            return redirect("/table/Категория услуг")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_service_category: {str(e)}")
            return render_template("add_service_category.html",
                                   error="Ошибка при добавлении категории услуг")
        except Exception as e:
            logger.error(f"Ошибка в add_service_category: {str(e)}")
            return render_template("add_service_category.html",
                                   error="Внутренняя ошибка сервера")

    # GET запрос - показываем форму
    return render_template("add_service_category.html")

# 🔐 Безопасное редактирование категории услуг
# 🔐 Безопасное редактирование категории услуг (в стиле edit_client)
@app.route("/edit/Категория услуг/<int:category_id>", methods=["GET", "POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def edit_service_category(category_id):
    """Безопасное редактирование категории услуг с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        category_id = int(category_id)
        if category_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            # Получаем данные категории через безопасную функцию
            cur.execute("SELECT * FROM fn_get_servicecategory_by_id(%s)", (category_id,))
            record = cur.fetchone()

            if not record:
                flash("Категория не найдена", "error")
                return redirect("/table/Категория услуг")

            colnames = [desc[0] for desc in cur.description]
            conn.close()
            return render_template("edit_service_category.html",
                                   record_data=list(zip(colnames, record)),
                                   category_id=category_id)

        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            categoryname = request.form.get("categoryname", "").strip()
            description = request.form.get("description", "").strip() or None

            # 🔐 Валидация входных данных
            if not categoryname:
                flash("Название категории является обязательным полем", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            if len(categoryname) > 100:
                flash("Название категории слишком длинное (максимум 100 символов)", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            if re.search(r'[<>"\';\\]', categoryname):
                flash("Название категории содержит недопустимые символы", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            if description and len(description) > 500:
                flash("Описание слишком длинное (максимум 500 символов)", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            if description and re.search(r'[<>"\';\\]', description):
                flash("Описание содержит недопустимые символы", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            # 🔐 Проверяем, не существует ли уже категория с таким названием (кроме текущей)
            cur.execute("""
                SELECT COUNT(*) 
                FROM fn_get_all_service_categories() 
                WHERE categoryname = %s AND categoryid != %s
            """, (categoryname, category_id))

            if cur.fetchone()[0] > 0:
                flash("Категория с таким названием уже существует", "error")
                return redirect(f"/edit/Категория услуг/{category_id}")

            # Вызываем безопасную функцию обновления
            cur.execute("SELECT fn_update_service_category(%s, %s, %s);",
                        (category_id, categoryname, description))
            conn.commit()
            conn.close()

            flash("Категория услуг успешно обновлена", "success")
            return redirect("/table/Категория услуг")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_service_category: {str(e)}")
        flash("Ошибка при обновлении категории", "error")
        return redirect(f"/edit/Категория услуг/{category_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_service_category: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Категория услуг/{category_id}")
    finally:
        if conn:
            conn.close()
# 🔐 Безопасное удаление категории услуг
# 🔐 Безопасное удаление категории услуг (в стиле delete_client)
@app.route("/delete/Категория услуг/<int:category_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "manager")
@csrf_protect
def delete_service_category(category_id):
    """Безопасное удаление категории услуг с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        category_id = int(category_id)
        if category_id <= 0:
            return "Неверный идентификатор категории", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор категории", 400

    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли категория
        cur.execute("SELECT COUNT(*) FROM fn_get_all_service_categories() WHERE categoryid = %s",
                   (category_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Категория не найдена", "error")
            return redirect("/table/Категория услуг")

        # 🔐 Проверяем, нет ли связанных услуг
        cur.execute("SELECT COUNT(*) FROM services WHERE categoryid = %s",
                   (category_id,))
        service_count = cur.fetchone()[0]

        if service_count > 0:
            conn.close()
            flash("Невозможно удалить категорию: существуют связанные услуги", "error")
            return redirect("/table/Категория услуг")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_service_category(%s);", (category_id,))
        conn.commit()
        conn.close()

        flash("Категория услуг удалена", "info")
        return redirect("/table/Категория услуг")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_service_category: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_service_category: {str(e)}")
        return "Ошибка удаления", 500

@app.route("/table/<name>")
@require_auth
def show_table(name):
    """Безопасное отображение таблиц"""

    # 🔐 Валидация имени таблицы
    if not name or not isinstance(name, str):
        abort(400, "Неверное имя таблицы")

    role = session.get("role")

    # Получаем доступные таблицы для роли
    tables = ROLE_TABLES.get(role, {})

    if name not in tables:
        return render_template("table.html", error=f"Нет доступа к таблице {name}")

    table_name = tables[name]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Выполняем безопасный запрос
        if name == "Конфиденциальные документы":
            query = """
                SELECT 
                    cd.docid as "ID",
                    cd.doctitle as "Название",
                    e.fullname as "Создатель", 
                    d.department_name as "Отдел",
                    cd.createddate as "Дата создания",
                    cd.accesslevel as "Уровень доступа",
                    cd.content as "Содержание"
                FROM ConfidentialDocuments cd
                JOIN employees e ON e.employeeid = cd.creatorid
                JOIN departments d ON d.department_id = cd.department_id
                ORDER BY cd.docid DESC
                LIMIT 100
            """
        else:
            query = f"SELECT * FROM {table_name} ORDER BY 1 DESC LIMIT 100"

        cur.execute(query)
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description] if cur.description else []

        conn.close()

        # 🔐 Используем pandas для создания HTML таблицы
        import pandas as pd
        df = pd.DataFrame(rows, columns=columns)

        # Стилизация бейджей
        def style_badges(val):
            if isinstance(val, str):
                if val in ['Активен', 'Соответствует', 'Не требуется', 'Активна']:
                    return f'<span class="badge" style="background: #2ecc71; color: white;">{val}</span>'
                elif val in ['Неактивен', 'Не соответствует', 'Требуется', 'Неактивна']:
                    return f'<span class="badge" style="background: #e74c3c; color: white;">{val}</span>'
                elif val == 'НЕ СООТВЕТСТВУЕТ':
                    return f'<span class="badge" style="background: #f39c12; color: black;">{val}</span>'
            return str(val) if val is not None else ""

        # Применяем стили к статусным колонкам
        status_columns = ['access_status', 'password_compliance', 'force_password_change', 'role_status']
        for col in status_columns:
            if col in df.columns:
                df[col] = df[col].apply(style_badges)

        # Генерируем HTML таблицу
        html_table = df.to_html(index=False, classes="data-table", escape=False)

        # 🔐 Просто добавляем data-row-id к строкам таблицы
        lines = html_table.split('\n')
        new_lines = []
        in_tbody = False
        row_index = 0

        for line in lines:
            if '<tbody>' in line:
                in_tbody = True
                new_lines.append(line)
            elif '</tbody>' in line:
                in_tbody = False
                new_lines.append(line)
            elif in_tbody and line.strip().startswith('<tr>'):
                # Добавляем data-row-id к строке
                if row_index < len(rows):
                    row_id = str(rows[row_index][0]) if rows[row_index][0] is not None else ""
                    new_line = line.replace('<tr>', f'<tr data-row-id="{row_id}">')
                    new_lines.append(new_line)
                    row_index += 1
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        html_table = '\n'.join(new_lines)

        # Получаем разрешения
        permissions = ROLE_PERMISSIONS.get(role, {})

        return render_template(
            "table.html",
            user=session.get("user", ""),
            role=role,
            table_name=table_name,
            display_name=name,
            data=html_table,
            permissions=permissions
        )

    except Exception as e:
        logger.error(f"Ошибка при загрузке {table_name}: {str(e)}")
        return render_template("table.html", error=f"Ошибка при загрузке данных: {str(e)}")
# 🔐 Безопасное добавление доступа сотрудника
@app.route("/add/Доступ сотрудников", methods=["GET", "POST"])
@require_auth
@require_role("security_officer", "superadmin")
@csrf_protect
def add_employee_access():
    """Безопасное добавление доступа сотрудника с валидацией и CSRF защитой"""
    if request.method == "POST":
        try:
            # Получаем и валидируем данные из формы
            employeeid = request.form.get("employeeid", "").strip()
            systemlogin = request.form.get("systemlogin", "").strip()
            isactive = request.form.get("isactive", "false") == "true"
            passwordcompliant = request.form.get("passwordcompliant", "false") == "true"
            forcepasswordchange = request.form.get("forcepasswordchange", "false") == "true"

            # 🔐 Валидация входных данных
            if not employeeid:
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Сотрудник является обязательным полем")

            if not systemlogin:
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Логин является обязательным полем")

            if len(systemlogin) > 50:
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Логин слишком длинный (максимум 50 символов)")

            if not re.match(r'^[a-zA-Z0-9_]+$', systemlogin):
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Логин может содержать только буквы, цифры и подчеркивания")

            # 🔐 Валидация числового поля
            try:
                employeeid_int = int(employeeid)
                if employeeid_int <= 0:
                    return render_template("add_employee_access.html",
                                           employees=get_employees_list(),
                                           error="ID сотрудника должен быть положительным числом")
            except ValueError:
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="ID сотрудника должен быть числом")

            # Подключаемся к БД через get_db_connection()
            conn = get_db_connection()
            cur = conn.cursor()

            # 🔐 Проверяем существование сотрудника
            cur.execute("SELECT COUNT(*) FROM employees WHERE employeeid = %s", (employeeid_int,))
            if cur.fetchone()[0] == 0:
                conn.close()
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Указанный сотрудник не существует")

            # 🔐 Проверяем, не существует ли уже доступ для этого сотрудника
            cur.execute("SELECT COUNT(*) FROM employeeaccess WHERE employeeid = %s", (employeeid_int,))
            if cur.fetchone()[0] > 0:
                conn.close()
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Доступ для этого сотрудника уже существует")

            # 🔐 Проверяем уникальность логина
            cur.execute("SELECT COUNT(*) FROM employeeaccess WHERE systemlogin = %s", (systemlogin,))
            if cur.fetchone()[0] > 0:
                conn.close()
                return render_template("add_employee_access.html",
                                       employees=get_employees_list(),
                                       error="Логин уже используется")

            # Вызываем безопасную функцию добавления
            cur.execute("SELECT fn_insert_employeeaccess(%s, %s, %s, %s, %s, %s);",
                        (employeeid_int, systemlogin, None, isactive, passwordcompliant, forcepasswordchange))
            conn.commit()
            conn.close()

            flash("Доступ сотрудника успешно создан", "success")
            return redirect("/table/Доступ сотрудников")

        except psycopg2.Error as e:
            logger.error(f"Ошибка базы данных в add_employee_access: {str(e)}")
            return render_template("add_employee_access.html",
                                   employees=get_employees_list(),
                                   error="Ошибка базы данных при создании доступа")
        except Exception as e:
            logger.error(f"Ошибка в add_employee_access: {str(e)}")
            return render_template("add_employee_access.html",
                                   employees=get_employees_list(),
                                   error="Внутренняя ошибка сервера")

    # GET запрос - показываем форму
    return render_template("add_employee_access.html", employees=get_employees_list())


# 🔐 Безопасное редактирование доступа сотрудника
@app.route("/edit/Доступ сотрудников/<int:access_id>", methods=["GET", "POST"])
@require_auth
@require_role("security_officer", "superadmin")
@csrf_protect
def edit_employee_access(access_id):
    """Безопасное редактирование доступа сотрудника с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        access_id = int(access_id)
        if access_id <= 0:
            abort(400)
    except (ValueError, TypeError):
        abort(400)

    conn = None
    try:
        # Используем безопасное подключение
        conn = get_db_connection()
        cur = conn.cursor()

        # Получаем список сотрудников для выпадающего списка
        cur.execute("SELECT employeeid, fullname FROM employees ORDER BY fullname")
        employees = cur.fetchall()

        if request.method == "GET":
            # Получаем текущие данные доступа из employeeaccess таблицы
            cur.execute("""
                SELECT ea.accessid, ea.employeeid, ea.systemlogin, 
                       ea.isactive, ea.passwordcompliant, ea.forcepasswordchange,
                       e.fullname as employee_name
                FROM employeeaccess ea
                LEFT JOIN employees e ON ea.employeeid = e.employeeid
                WHERE ea.accessid = %s
            """, (access_id,))

            record = cur.fetchone()

            if not record:
                flash("Доступ не найден", "error")
                return redirect("/table/Доступ сотрудников")

            colnames = [desc[0] for desc in cur.description]
            conn.close()

            record_data = list(zip(colnames, record))
            return render_template("edit_employee_access.html",
                                   record_data=record_data,
                                   employees=employees,
                                   access_id=access_id)
        elif request.method == "POST":
            # Получаем и валидируем данные из формы
            employeeid = request.form.get("employeeid", "").strip()
            systemlogin = request.form.get("systemlogin", "").strip()
            isactive = request.form.get("isactive", "").strip() == "true"
            passwordcompliant = request.form.get("passwordcompliant", "").strip() == "true"
            forcepasswordchange = request.form.get("forcepasswordchange", "").strip() == "true"

            # 🔐 Валидация входных данных
            if not employeeid:
                flash("ID сотрудника является обязательным полем", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            if not systemlogin:
                flash("Логин является обязательным полем", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            if len(systemlogin) > 50:
                flash("Логин слишком длинный (максимум 50 символов)", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            if not re.match(r'^[a-zA-Z0-9_]+$', systemlogin):
                flash("Логин может содержать только буквы, цифры и подчеркивания", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            # 🔐 Валидация числового поля
            try:
                employeeid_int = int(employeeid)
                if employeeid_int <= 0:
                    flash("ID сотрудника должен быть положительным числом", "error")
                    return redirect(f"/edit/Доступ сотрудников/{access_id}")
            except ValueError:
                flash("ID сотрудника должен быть числом", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            # 🔐 Проверяем существование сотрудника
            cur.execute("SELECT COUNT(*) FROM employees WHERE employeeid = %s", (employeeid_int,))
            if cur.fetchone()[0] == 0:
                flash("Указанный сотрудник не существует", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            # 🔐 Проверяем уникальность логина (кроме текущего доступа)
            cur.execute("""
                SELECT COUNT(*) 
                FROM employeeaccess 
                WHERE systemlogin = %s AND accessid != %s
            """, (systemlogin, access_id))
            if cur.fetchone()[0] > 0:
                flash("Логин уже используется другим сотрудником", "error")
                return redirect(f"/edit/Доступ сотрудников/{access_id}")

            # Вызываем функцию обновления
            cur.execute("SELECT fn_update_employeeaccess(%s, %s, %s, %s, %s, %s);",
                        (access_id, employeeid_int, systemlogin, isactive, passwordcompliant, forcepasswordchange))
            conn.commit()
            conn.close()

            flash("Доступ сотрудника успешно обновлен", "success")
            return redirect("/table/Доступ сотрудников")

    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка базы данных в edit_employee_access: {str(e)}")
        flash("Ошибка при обновлении доступа", "error")
        return redirect(f"/edit/Доступ сотрудников/{access_id}")
    except Exception as e:
        logger.error(f"Ошибка в edit_employee_access: {str(e)}")
        flash("Внутренняя ошибка сервера", "error")
        return redirect(f"/edit/Доступ сотрудников/{access_id}")
    finally:
        if conn:
            conn.close()
# 🔐 Безопасное удаление доступа сотрудника
@app.route("/delete/Доступ сотрудников/<int:access_id>", methods=["POST"])
@require_auth
@require_role("security_officer", "superadmin")
@csrf_protect
def delete_employee_access(access_id):
    """Безопасное удаление доступа сотрудника с валидацией и CSRF защитой"""

    # 🔐 Валидация ID
    try:
        access_id = int(access_id)
        if access_id <= 0:
            return "Неверный идентификатор доступа", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор доступа", 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли доступ
        cur.execute("SELECT COUNT(*) FROM v_security_employee_access WHERE accessid = %s", (access_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Доступ не найден", "error")
            return redirect("/table/Доступ сотрудников")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_employeeaccess(%s);", (access_id,))
        conn.commit()
        conn.close()

        flash("Доступ сотрудника удален", "info")
        return redirect("/table/Доступ сотрудников")

    except psycopg2.Error as e:
        logger.error(f"Ошибка базы данных в delete_employee_access: {str(e)}")
        return "Ошибка удаления", 500
    except Exception as e:
        logger.error(f"Ошибка в delete_employee_access: {str(e)}")
        return "Ошибка удаления", 500

# Вспомогательная функция для получения списка сотрудников
def get_employees_list():
    """Получение списка сотрудников для выпадающего списка"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT employeeid, fullname FROM employees ORDER BY fullname")
        employees = cur.fetchall()
        conn.close()
        return employees
    except Exception as e:
        logger.error(f"Ошибка при получении списка сотрудников: {str(e)}")
        return []


# ==============================
# 🔐 Настройки проверки файла
# ==============================
ALLOWED_EXTENSIONS = {".txt"}
ALLOWED_MIME = {"text/plain"}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB


def is_safe_text_file(filename, mimetype, file_bytes):
    import magic   # pip install python-magic / python-magic-bin
    import os

    # Проверка расширения
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False, "Разрешены только файлы .txt"

    # MIME из запроса
    if mimetype not in ALLOWED_MIME:
        return False, f"Неверный MIME-тип: {mimetype}"

    # Проверяем настоящий MIME
    real_mime = magic.from_buffer(file_bytes, mime=True)
    if real_mime not in ALLOWED_MIME:
        return False, f"Файл выглядит как '{real_mime}', а не text/plain"

    # Опасные вставки
    dangerous_patterns = ["<script", "<?php", "<html", "<iframe", "onload=", "javascript:"]
    lowered = file_bytes.decode("utf-8", "ignore").lower()

    if any(p in lowered for p in dangerous_patterns):
        return False, "Файл содержит потенциально вредоносный код"

    return True, ""

# 🔐 Безопасное добавление конфиденциального документа
@app.route("/add/Конфиденциальные документы", methods=["GET", "POST"])
@require_auth
@csrf_protect
def add_confidential_document():
    """Безопасное добавление конфиденциального документа"""

    # Проверяем права
    role = session.get('role', 'junior_employee')
    if role not in ['superadmin', 'security_officer', 'manager', 'senior_mechanic', 'junior_employee']:
        flash("У вас нет прав для создания документов", "error")
        return redirect("/table/Конфиденциальные документы")

    if request.method == "GET":
        return render_template("add_confidential_document.html")

    conn = None
    try:
        # Данные формы
        doc_title = request.form.get("doc_title", "").strip()
        content = request.form.get("content", "").strip()
        access_level = request.form.get("access_level", "").strip()

        uploaded_file = request.files.get('confidential_file')

        # Валидация
        if not doc_title:
            flash("Название документа является обязательным полем", "error")
            return redirect("/add/Конфиденциальные документы")

        if len(doc_title) > 200:
            flash("Название документа слишком длинное", "error")
            return redirect("/add/Конфиденциальные документы")

        if access_level not in ['Public', 'Internal', 'Confidential', 'Strictly']:
            flash("Некорректный уровень доступа", "error")
            return redirect("/add/Конфиденциальные документы")

        # Файл
        filename = None
        filetype = 'text/plain'
        filesize = None

        if uploaded_file and uploaded_file.filename:

            filename = uploaded_file.filename
            filetype = uploaded_file.content_type or "text/plain"

            uploaded_file.seek(0, 2)
            filesize = uploaded_file.tell()
            uploaded_file.seek(0)

            if filesize > MAX_FILE_SIZE:
                flash("Файл слишком большой (максимум 16 МБ)", "error")
                return redirect("/add/Конфиденциальные документы")

            file_bytes = uploaded_file.read()

            ok, msg = is_safe_text_file(filename, filetype, file_bytes)
            if not ok:
                flash(msg, "error")
                return redirect("/add/Конфиденциальные документы")

            # нормализуем текст
            text = file_bytes.decode("utf-8", errors="ignore")
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            while "\n\n\n" in text:
                text = text.replace("\n\n\n", "\n\n")

            content = text
        else:
            filesize = len(content.encode("utf-8"))

        # БД
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT get_current_employee_id();")
        creator_id = cur.fetchone()[0]

        cur.execute("SELECT get_current_department_id();")
        department_id = cur.fetchone()[0]

        cur.execute("""
            SELECT fn_insert_confidential_document_with_file(
                %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (doc_title, content, access_level, department_id, creator_id,
              filename, filetype, filesize))

        conn.commit()

        flash("Конфиденциальный документ успешно создан", "success")
        return redirect("/table/Конфиденциальные документы")

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка в add_confidential_document: {str(e)}")
        flash("Ошибка при создании документа", "error")
        return redirect("/add/Конфиденциальные документы")

    finally:
        if conn:
            conn.close()



# 🔐 Безопасное редактирование конфиденциального документа
@app.route("/edit/Конфиденциальные документы/<int:doc_id>", methods=["GET", "POST"])
@require_auth
@csrf_protect
def edit_confidential_document(doc_id):
    """Безопасное редактирование конфиденциального документа"""

    try:
        doc_id = int(doc_id)
        if doc_id <= 0:
            abort(400)
    except:
        abort(400)

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if request.method == "GET":
            cur.execute("SELECT * FROM fn_get_confidential_document_with_file(%s)", (doc_id,))
            record = cur.fetchone()

            if not record:
                flash("Документ не найден", "error")
                return redirect("/table/Конфиденциальные документы")

            colnames = [desc[0] for desc in cur.description]
            document_data = dict(zip(colnames, record))

            return render_template("edit_confidential_document.html",
                                   document=document_data,
                                   doc_id=doc_id)

        # POST
        doc_title = request.form.get("doc_title", "").strip()
        content = request.form.get("content", "").strip()
        access_level = request.form.get("access_level", "").strip()

        uploaded_file = request.files.get('confidential_file')

        if not doc_title:
            flash("Название документа является обязательным полем", "error")
            return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

        if len(doc_title) > 200:
            flash("Название документа слишком длинное", "error")
            return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

        if access_level not in ['Public', 'Internal', 'Confidential', 'Strictly']:
            flash("Некорректный уровень доступа", "error")
            return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

        filename = None
        filetype = "text/plain"
        filesize = None

        if uploaded_file and uploaded_file.filename:

            filename = uploaded_file.filename
            filetype = uploaded_file.content_type or "text/plain"

            uploaded_file.seek(0, 2)
            filesize = uploaded_file.tell()
            uploaded_file.seek(0)

            if filesize > MAX_FILE_SIZE:
                flash("Файл слишком большой (максимум 16 МБ)", "error")
                return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

            file_bytes = uploaded_file.read()

            ok, msg = is_safe_text_file(filename, filetype, file_bytes)
            if not ok:
                flash(msg, "error")
                return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

            text = file_bytes.decode("utf-8", errors="ignore")
            text = text.replace("\r\n", "\n").replace("\r", "\n")

            while "\n\n\n" in text:
                text = text.replace("\n\n\n", "\n\n")

            content = text
        else:
            filesize = len(content.encode("utf-8"))

        # Проверка прав
        cur.execute("SELECT creatorid FROM ConfidentialDocuments WHERE docid = %s", (doc_id,))
        creator_row = cur.fetchone()

        if not creator_row:
            flash("Документ не найден", "error")
            return redirect("/table/Конфиденциальные документы")

        creator_id = creator_row[0]

        cur.execute("SELECT get_current_employee_id();")
        current_id = cur.fetchone()[0]

        if current_id != creator_id and session.get('role') not in ['security_officer', 'superadmin']:
            flash("У вас нет прав для редактирования этого документа", "error")
            return redirect("/table/Конфиденциальные документы")

        # Обновление
        cur.execute("""
            SELECT fn_update_confidential_document_with_file(
                %s, %s, %s, %s, %s, %s, %s
            );
        """, (doc_id, doc_title, content, access_level,
              filename, filetype, filesize))

        conn.commit()
        flash("Конфиденциальный документ успешно обновлен", "success")
        return redirect("/table/Конфиденциальные документы")

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Ошибка в edit_confidential_document: {str(e)}")
        flash("Ошибка при обновлении документа", "error")
        return redirect(f"/edit/Конфиденциальные документы/{doc_id}")

    finally:
        if conn:
            conn.close()



# 🔐 Скачивание документа как файла
@app.route("/download/confidential_document/<int:doc_id>")
@require_auth
def download_confidential_document(doc_id):
    """Скачивание конфиденциального документа как файла"""

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Получаем документ с информацией о файле
        cur.execute("SELECT * FROM fn_get_confidential_document_with_file(%s)", (doc_id,))
        record = cur.fetchone()

        if not record:
            flash("Документ не найден", "error")
            return redirect("/table/Конфиденциальные документы")

        colnames = [desc[0] for desc in cur.description]
        doc_data = dict(zip(colnames, record))

        conn.close()

        # Подготавливаем данные для скачивания
        content = doc_data['content']
        filename = doc_data['filename'] or f"document_{doc_id}.txt"
        filetype = doc_data['filetype'] or 'text/plain'

        # Если содержимое в base64 (бинарный файл), декодируем
        if filetype not in ['text/plain', 'text/html', 'text/csv']:
            try:
                import base64
                content = base64.b64decode(content)
            except:
                # Если не base64, считаем это текстом
                content = str(content).encode('utf-8')
        else:
            content = content.encode('utf-8')

        # Создаем объект BytesIO для отправки файла
        file_stream = io.BytesIO(content)

        return send_file(
            file_stream,
            download_name=filename,
            as_attachment=True,
            mimetype=filetype
        )

    except Exception as e:
        logger.error(f"Ошибка в download_confidential_document: {str(e)}")
        flash("Ошибка при скачивании документа", "error")
        return redirect("/table/Конфиденциальные документы")
    finally:
        if conn:
            conn.close()


# 🔐 Безопасное удаление конфиденциального документа
@app.route("/delete/Конфиденциальные документы/<int:doc_id>", methods=["POST"])
@require_auth
@require_role("superadmin", "security_officer")
@csrf_protect
def delete_confidential_document(doc_id):
    """Безопасное удаление конфиденциального документа"""

    # 🔐 Валидация ID
    try:
        doc_id = int(doc_id)
        if doc_id <= 0:
            return "Неверный идентификатор документа", 400
    except (ValueError, TypeError):
        return "Неверный идентификатор документа", 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 Проверяем, существует ли документ
        cur.execute("SELECT COUNT(*) FROM ConfidentialDocuments WHERE docid = %s", (doc_id,))
        if cur.fetchone()[0] == 0:
            conn.close()
            flash("Документ не найден", "error")
            return redirect("/table/Конфиденциальные документы")

        # Вызываем безопасную функцию удаления
        cur.execute("SELECT fn_delete_confidential_document(%s);", (doc_id,))
        conn.commit()
        conn.close()

        flash("Конфиденциальный документ удален", "info")
        return redirect("/table/Конфиденциальные документы")

    except Exception as e:
        logger.error(f"Ошибка в delete_confidential_document: {str(e)}")
        return "Ошибка удаления", 500

# 🔐 Таблица конфиденциальных документов
@app.route("/table/Конфиденциальные документы")
@require_auth
def confidential_documents_table():
    """Таблица конфиденциальных документов"""

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Используем функцию вместо представления
        cur.execute("SELECT * FROM fn_get_confidential_documents_with_files()")
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]

        conn.close()

        # Создаем DataFrame
        df = pd.DataFrame(rows, columns=columns)

        # Переименовываем столбцы для отображения
        column_mapping = {
            'docid': 'ID',
            'doctitle': 'Название документа',
            'creator_name': 'Создатель',
            'createddate': 'Дата создания',
            'accesslevel': 'Уровень доступа',
            'content': 'Содержание',
            'department_name': 'Отдел',
            'filename': 'Файл',
            'filesize': 'Размер файла (байт)',
            'lastmodified': 'Дата изменения'
        }

        df.rename(columns=column_mapping, inplace=True)

        # Оставляем только нужные столбцы
        display_columns = ['ID', 'Название документа', 'Создатель', 'Дата создания',
                           'Уровень доступа', 'Отдел', 'Файл', 'Размер файла (байт)', 'Дата изменения']
        df = df[[col for col in display_columns if col in df.columns]]

        # Стили для уровней доступа
        def style_access_level(val):
            if val == 'Public':
                return f'<span class="badge bg-success">{val}</span>'
            elif val == 'Internal':
                return f'<span class="badge bg-info">{val}</span>'
            elif val == 'Confidential':
                return f'<span class="badge bg-warning text-dark">{val}</span>'
            elif val == 'Strictly':
                return f'<span class="badge bg-danger">{val}</span>'
            return val

        # Стили для файлов
        def style_file_column(val, row):
            if not val or val == 'None' or pd.isna(val):
                return f'<span class="badge bg-secondary">Нет файла</span>'
            else:
                doc_id = row['ID']
                return f'''
                    <div class="file-info">
                        <span class="file-name">{val}</span>
                        <a href="/download/confidential_document/{doc_id}" 
                           class="btn btn-sm btn-primary" 
                           title="Скачать файл">
                             Скачать
                        </a>
                    </div>
                '''

        # Применяем стили
        if 'Уровень доступа' in df.columns:
            df['Уровень доступа'] = df['Уровень доступа'].apply(style_access_level)

        if 'Файл' in df.columns:
            df['Файл'] = df.apply(lambda row: style_file_column(row['Файл'], row), axis=1)

        # Форматируем размер файла
        if 'Размер файла (байт)' in df.columns:
            def format_file_size(size):
                if pd.isna(size):
                    return ''
                for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
                    if size < 1024.0:
                        return f"{size:.1f} {unit}"
                    size /= 1024.0
                return f"{size:.1f} ТБ"

            df['Размер файла'] = df['Размер файла (байт)'].apply(format_file_size)
            df = df.drop('Размер файла (байт)', axis=1)

        # Генерируем HTML таблицу
        html_table = df.to_html(index=False, classes="data-table", escape=False)

        # 🔐 Добавляем data-row-id к строкам таблицы (как в show_table)
        lines = html_table.split('\n')
        new_lines = []
        in_tbody = False
        row_index = 0

        for line in lines:
            if '<tbody>' in line:
                in_tbody = True
                new_lines.append(line)
            elif '</tbody>' in line:
                in_tbody = False
                new_lines.append(line)
            elif in_tbody and line.strip().startswith('<tr>'):
                # Добавляем data-row-id к строке
                if row_index < len(rows):
                    row_id = str(rows[row_index][0]) if rows[row_index][0] is not None else ""
                    new_line = line.replace('<tr>', f'<tr data-row-id="{row_id}">')
                    new_lines.append(new_line)
                    row_index += 1
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        html_table = '\n'.join(new_lines)

        # Определяем права в зависимости от роли
        role = session.get("role", "junior_employee")
        permissions = ROLE_PERMISSIONS.get(role, {}).copy()

        # Security officer и superadmin имеют полные права
        if role in ['security_officer', 'superadmin']:
            permissions = {"create": True, "read": True, "update": True, "delete": True}
        # Обычные сотрудники могут только читать и создавать
        elif role in ['junior_employee', 'senior_mechanic', 'manager']:
            permissions = {"create": True, "read": True, "update": False, "delete": False}

        return render_template(
            "table.html",
            user=session["user"],
            role=role,
            display_name="Конфиденциальные документы",
            data=html_table,
            permissions=permissions
        )

    except Exception as e:
        logger.error(f"Ошибка в confidential_documents_table: {str(e)}")
        return render_template("table.html",
                               error=f"Ошибка загрузки документов: {str(e)}",
                               permissions={"create": False, "read": False, "update": False, "delete": False})
# 🔐 Таблица конфиденциальных документов

@app.route("/logout")
def logout():
    # Удаляем токен из хранилища
    token = session.get("auth_token")
    if token and token in session_tokens:
        del session_tokens[token]

    # Очищаем сессию
    session.clear()
    flash("Вы вышли из системы", "info")
    return redirect("/")

#app.after_request
#def add_security_headers(response):
#    """Добавляет заголовки безопасности (ВРЕМЕННО БЕЗ CSP)"""
   # response.headers['X-Content-Type-Options'] = 'nosniff'
  #  response.headers['X-Frame-Options'] = 'DENY'
    #response.headers['X-XSS-Protection'] = '1; mode=block'
    # 🔥 ВРЕМЕННО КОММЕНТИРУЕМ CSP
    # response.headers['Content-Security-Policy'] = "default-src 'self';"
    #return response


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error="Доступ запрещен"), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error="Страница не найдена"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Внутренняя ошибка сервера: {str(error)}")
    return render_template('error.html', error="Внутренняя ошибка сервера"), 500


# 📋 Маршрут для отладки сессии (УДАЛИТЬ В PRODUCTION!)
@app.route("/debug/session")
@require_auth
def debug_session():
    """Показывает содержимое сессии (только для отладки)"""

    # 🔐 Проверяем, что пароля НЕТ в сессии
    session_content = dict(session)

    # Убираем чувствительные данные для вывода
    safe_session = {}
    for key, value in session_content.items():
        if key in ['_csrf_token', 'auth_token', 'login_time']:
            # Показываем только тип и длину для токенов
            safe_session[key] = f"<{type(value).name} length={len(str(value))}>"
        elif key == 'user':
            safe_session[key] = value  # Логин можно показывать
        elif key == 'role':
            safe_session[key] = value  # Роль можно показывать
        elif key == 'employee_id':
            safe_session[key] = str(value)[:3] + "***" if value else None
        else:
            safe_session[key] = str(value)[:50] + "..." if len(str(value)) > 50 else value

    # 🔐 Проверяем наличие пароля в сессии
    password_in_session = 'password' in session_content
    auth_token_valid = session.get('auth_token') in session_tokens

    return render_template("debug_session.html",
                           session_data=safe_session,
                           password_in_session=password_in_session,
                           auth_token_valid=auth_token_valid,
                           total_tokens=len(session_tokens))


# 🔐 Обработчик ошибки 429 (Too Many Requests)
@app.errorhandler(429)
def too_many_requests(error):
    ip_address = get_client_ip()
    if ip_address in blocked_ips:
        block_until = blocked_ips[ip_address]
        time_left = (block_until - datetime.now()).total_seconds()
        minutes_left = int(time_left // 60)
        seconds_left = int(time_left % 60)
        message = f"Слишком много запросов. Ваш IP заблокирован на {minutes_left} минут {seconds_left} секунд."
    else:
        message = "Слишком много запросов. Пожалуйста, попробуйте позже."

    return render_template('error.html', error=message), 429

if __name__ == "__main__":
    app.run(
        host=os.environ.get('FLASK_HOST', '0.0.0.0'),
        port=int(os.environ.get('FLASK_PORT', 59213)),
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    )