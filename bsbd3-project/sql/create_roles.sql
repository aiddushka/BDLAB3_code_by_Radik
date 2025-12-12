CREATE ROLE manager;
CREATE ROLE senior_mechanic;
CREATE ROLE junior_employee;
CREATE ROLE security_officer;
CREATE ROLE superadmin;

-- Механик (Алексей)
CREATE USER a_smirnov WITH PASSWORD 'StrongPassword1!';
-- Менеджер (Елена)
CREATE USER e_volkova WITH PASSWORD 'StrongPassword2!';
-- Диагност (Игорь)
CREATE USER i_fedorov WITH PASSWORD 'StrongPassword3!';
-- Бухгалтер (Татьяна)
CREATE USER t_grigoreva WITH PASSWORD 'StrongPassword4!';
-- Безопасник (Михаил)
CREATE USER m_danilov WITH PASSWORD 'StrongPassword5!';
-- Главный админ (Жорик)
CREATE USER z_starkov WITH PASSWORD 'SuperAdmin999!';

CREATE USER i_ivanov WITH PASSWORD 'StrongP@ssw0rd!';
CREATE USER yeahsanty WITH PASSWORD 'StrongP@ssw0rd!';


-- Полный доступ супер-админу
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO superadmin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO superadmin;

-- Пример для manager
GRANT SELECT, INSERT, UPDATE ON employees, employee_roles, orders, clients, departments TO manager;
GRANT SELECT, INSERT, UPDATE ON services, orderservices, servicecategories TO manager;

-- Для senior_mechanic
GRANT SELECT, INSERT, UPDATE ON orders, orderservices, services, cars TO senior_mechanic;

-- Для junior_employee
GRANT SELECT ON orders, orderservices, services, cars TO junior_employee;
GRANT INSERT, UPDATE ON orderservices TO junior_employee;

-- Для security_officer
GRANT SELECT, UPDATE ON audit_log, encrypted_data_access_log, encryption_keys TO security_officer;

-- Если нужно дать доступ к sequences для автоинкремента
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO manager, senior_mechanic, junior_employee;




-- Привязка пользователей к ролям
GRANT superadmin TO z_starkov;

GRANT manager TO e_volkova;

GRANT senior_mechanic TO i_fedorov;
GRANT junior_employee TO a_smirnov;

GRANT security_officer TO m_danilov;

-- Логин "i.ivanov" (сотрудник, созданный через функцию) пусть будет junior_employee
GRANT junior_employee TO i_ivanov;  -- если у тебя есть соответствующий login

GRANT manager TO yeahsanty;




-- 3️⃣ Важные моменты
-- GRANT выполняется к ролям, а не напрямую к пользователям. Пользователи просто наследуют права.
-- Для новых таблиц после создания нужно запускать GRANT снова, либо использовать:

-- ALTER DEFAULT PRIVILEGES IN SCHEMA public
-- GRANT SELECT, INSERT, UPDATE ON TABLES TO manager;
