import os
import sqlite3
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "app.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    # seed roles
    roles_count = conn.execute("SELECT COUNT(*) AS c FROM roles").fetchone()["c"]
    if roles_count == 0:
        conn.execute(
            "INSERT INTO roles(name, description) VALUES (?, ?)",
            ("Администратор", "Полный доступ к CRUD и журналу"),
        )
        conn.execute(
            "INSERT INTO roles(name, description) VALUES (?, ?)",
            ("Пользователь", "Доступ к своему профилю и журналу"),
        )

    # seed admin
    admin = conn.execute("SELECT id FROM users WHERE login = ?", ("admin",)).fetchone()
    if admin is None:
        conn.execute(
            """
            INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id)
            VALUES (?, ?, ?, ?, ?, (SELECT id FROM roles WHERE name = ?))
            """,
            (
                "admin",
                generate_password_hash("Admin12345"),
                "Остапенко",
                "Святослав",
                "Русланович",
                "Администратор",
            ),
        )
        print("Создан пользователь admin / Admin12345")

    # seed user
    user = conn.execute("SELECT id FROM users WHERE login = ?", ("user",)).fetchone()
    if user is None:
        conn.execute(
            """
            INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id)
            VALUES (?, ?, ?, ?, ?, (SELECT id FROM roles WHERE name = ?))
            """,
            (
                "user",
                generate_password_hash("User12345"),
                "Иванов",
                "Иван",
                "Иванович",
                "Пользователь",
            ),
        )
        print("Создан пользователь user / User12345")

    conn.commit()
    conn.close()
    print("БД готова:", DB_PATH)


if __name__ == "__main__":
    main()