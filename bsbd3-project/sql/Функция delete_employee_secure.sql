CREATE OR REPLACE FUNCTION delete_employee_secure(
    p_employee_id INT,
    p_deleted_by_id INT  -- ID пользователя, выполняющего удаление
)
RETURNS BOOLEAN AS
$$
DECLARE
    v_exists INT;
BEGIN
    ---------------------------------------------------------
    -- 0. Проверяем, существует ли сотрудник
    ---------------------------------------------------------
    SELECT COUNT(*)
    INTO v_exists
    FROM employees
    WHERE employeeid = p_employee_id;

    IF v_exists = 0 THEN
        RAISE EXCEPTION 'Сотрудник с ID % не найден', p_employee_id;
    END IF;

    ---------------------------------------------------------
    -- 1. Удаляем роль сотрудника
    ---------------------------------------------------------
    DELETE FROM employee_roles
    WHERE employee_id = p_employee_id;

    ---------------------------------------------------------
    -- 2. Удаляем доступ (employeeaccess)
    ---------------------------------------------------------
    DELETE FROM employeeaccess
    WHERE employeeid = p_employee_id;

    ---------------------------------------------------------
    -- 3. Удаляем историю паролей
    ---------------------------------------------------------
    DELETE FROM password_history
    WHERE employee_id = p_employee_id;

    ---------------------------------------------------------
    -- 4. Удаляем запись сотрудника
    ---------------------------------------------------------
    DELETE FROM employees
    WHERE employeeid = p_employee_id;

    ---------------------------------------------------------
    -- 5. (Опционально) логируем удаление
    ---------------------------------------------------------
    -- INSERT INTO security_audit_log(action_type, entity, entity_id, performed_by, action_time)
    -- VALUES ('delete', 'employee', p_employee_id, p_deleted_by_id, NOW());

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;




---------------------------------------------------------
--                ШАБЛОН
---------------------------------------------------------
SELECT delete_employee_secure(15, 1);
-- первое кого удаляем, второе кто удаляет