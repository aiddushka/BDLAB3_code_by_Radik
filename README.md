Велкоме в читалку.

1) Загрузи репозиторий к себе: 
`git clone https://github.com/aiddushka/BDLAB3_code_by_Radik.git`
2) Зайди в режим psql: `sudo -u postgres`
3) Создай БД: `CREATE DATABASE autodb;` и выйди из psql `\q`
4) Зайди в папку с бекапом .\bsbd3-project\backups
5) И востанови данные: `sudo -u postgres pg_restore -d autodb autodb.backup`
6) Зайди в базу данных `sudo -u postgres` далее в psql `\c autodb`
7) Создание роли: `CREATE ROLE app_user WITH LOGIN PASSWORD strongpassword;`
8) Дать все привилегии на ВСЕ существующие таблицы `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;`
9) Запустить main.py

Пароли:
Wi-fi: BSBD_Lab3 Пароль: 1r2e3w4q
ssh: ip: 192.168.1.101 пароль root: joo8aaca6ooShi 

Пользователи:
