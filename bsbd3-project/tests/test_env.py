import os
from dotenv import load_dotenv

# Загрузка .env
load_dotenv()

print("DATABASE_URL =", os.getenv("DATABASE_URL"))
print("SECRET_KEY =", os.getenv("SECRET_KEY"))
