CREATE OR REPLACE FUNCTION add_employee_secure(
    p_fullname TEXT,
    p_position TEXT,
    p_phone TEXT,
    p_email TEXT,
    p_department_id INT,
    p_salary NUMERIC,
    p_system_login TEXT,
    p_password TEXT,
    p_role_id INT,
    p_created_by_id INT -- ID пользователя, создавшего сотрудника
)
RETURNS INT AS
$$
DECLARE
    v_employee_id INT;
    v_login_encrypted BYTEA;
    v_phone_encrypted BYTEA;
    v_email_encrypted BYTEA;
    v_password_hash TEXT;
BEGIN
    -- Проверка политики пароля
    PERFORM check_password_policy(p_system_login, p_password);

    -- Генерация MD5-хеша (как в твоей системе)
    v_password_hash := md5(p_password);

    -- Шифрование телефона
    v_phone_encrypted := pgp_sym_encrypt(
        p_phone,
        get_encryption_key('phone_encryption_key_2024'),
        'cipher-algo=aes256'
    );

    -- Шифрование email
    v_email_encrypted := pgp_sym_encrypt(
        p_email,
        get_encryption_key('email_encryption_key_2024'),
        'cipher-algo=aes256'
    );

    -- Шифрование логина
    v_login_encrypted := pgp_sym_encrypt(
        p_system_login,
        get_encryption_key('login_encryption_key_2024'),
        'cipher-algo=aes256'
    );

    ---------------------------------------------------------
    -- 1. Создание сотрудника
    ---------------------------------------------------------
    INSERT INTO employees (
        fullname,
        position,
        phone,
        email,
        department_id,
        hiredate,
        salary,
        phone_encrypted,
        email_encrypted
    )
    VALUES (
        p_fullname,
        p_position,
        p_phone,
        p_email,
        p_department_id,
        NOW(),
        p_salary,
        v_phone_encrypted,
        v_email_encrypted
    )
    RETURNING employeeid INTO v_employee_id;

    ---------------------------------------------------------
    -- 2. Добавление доступа
    ---------------------------------------------------------
    INSERT INTO employeeaccess (
        employeeid,
        systemlogin,
        issuedate,
        isactive,
        passwordhash,
        passwordchangeddate,
        passwordcompliant,
        forcepasswordchange,
        systemlogin_encrypted
    )
    VALUES (
        v_employee_id,
        p_system_login,
        NOW(),
        TRUE,
        v_password_hash,
        NOW(),
        TRUE,
        FALSE,
        v_login_encrypted
    );

    ---------------------------------------------------------
    -- 3. Назначение роли
    ---------------------------------------------------------
    INSERT INTO employee_roles (
        employee_role_id,
        employee_id,
        role_id,
        assigned_date,
        assigned_by,
        is_active
    )
    VALUES (
        DEFAULT,
        v_employee_id,
        p_role_id,
        NOW(),
        p_created_by_id, -- INTEGER, теперь корректно
        TRUE
    );

    ---------------------------------------------------------
    -- 4. Запись в историю
    ---------------------------------------------------------
    INSERT INTO password_history (
        employee_id,
        password_hash,
        change_date,
        changed_by
    )
    VALUES (
        v_employee_id,
        v_password_hash,
        NOW(),
        p_created_by_id
    );

    RETURN v_employee_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;







---------------------------------------------------------
--                ШАБЛОН
---------------------------------------------------------
SELECT add_employee_secure(
'Иванов Иван',
'Инженер',
'+7-999-00-00-11',
'ivanov@example.com',
3,
85000,
'i.ivanov',
'StrongP@ssw0rd!',
4,     -- роль
1      -- created_by_id = employeeid администратора
);