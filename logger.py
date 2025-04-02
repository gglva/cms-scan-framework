import logging
import os

# Шлях до лог-файлу
LOG_FILE = "logs.txt"

# Очистка лог-файлу при кожному запуску
if os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as file:
        file.write("")  # Очищуємо файл

# Налаштування логування
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,  # Логуватимемо все від INFO і вище
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Логер, який можна імпортувати в інші модулі
logger = logging.getLogger()

# Додаємо виведення логів у консоль
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.info("Logger initialized and log file cleared.")
