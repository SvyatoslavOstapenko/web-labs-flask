import os
import re
import sqlite3
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, request, redirect, url_for, flash, g, abort
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-ostapenko-241-327"

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "app.db")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации."
login_manager.login_message_category = "warning"


# ---------- DB helpers ----------
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_one(sql, params=()):
    return get_db().execute(sql, params).fetchone()


def db_all(sql, params=()):
    return get_db().execute(sql, params).fetchall()


def db_exec(sql, params=()):
    cur = get_db().execute(sql, params)
    get_db().commit()
    return cur


# ---------- Auth ----------
class User(UserMixin):
    def __init__(self, user_id: int, login: str):
        self.id = str(user_id)
        self.login = login


@login_manager.user_loader
def load_user(user_id: str):
    row = db_one("SELECT id, login FROM users WHERE id = ?", (user_id,))
    if row:
        return User(row["id"], row["login"])
    return None


def is_safe_url(target: str) -> bool:
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# ---------- Validation ----------
LOGIN_RE = re.compile(r"^[A-Za-z0-9]{5,}$")

PWD_ALLOWED_RE = re.compile(r'^[A-Za-zА-Яа-яЁё0-9~!?@#$%^&*_\-+\(\)\[\]\{\}><\/\\\|"\'\.,:;]+$')


def validate_login(login: str) -> str | None:
    if not login:
        return "Поле не может быть пустым."
    if not LOGIN_RE.match(login):
        return "Логин должен быть не короче 5 символов и содержать только латинские буквы и цифры."
    return None


def validate_required(value: str) -> str | None:
    if not value:
        return "Поле не может быть пустым."
    return None


def validate_password(pwd: str) -> list[str]:
    errors: list[str] = []
    if not pwd:
        return ["Поле не может быть пустым."]

    if len(pwd) < 8:
        errors.append("Пароль должен быть не менее 8 символов.")
    if len(pwd) > 128:
        errors.append("Пароль должен быть не более 128 символов.")
    if re.search(r"\s", pwd):
        errors.append("Пароль не должен содержать пробелы.")
    if not PWD_ALLOWED_RE.match(pwd):
        errors.append("Пароль содержит недопустимые символы.")
    if not re.search(r"[A-ZА-ЯЁ]", pwd):
        errors.append("Пароль должен содержать хотя бы одну заглавную букву.")
    if not re.search(r"[a-zа-яё]", pwd):
        errors.append("Пароль должен содержать хотя бы одну строчную букву.")
    if not re.search(r"[0-9]", pwd):
        errors.append("Пароль должен содержать хотя бы одну цифру.")

    return errors


def roles_list():
    return db_all("SELECT id, name, description FROM roles ORDER BY name")


def fio_from_row(row) -> str:
    parts = [row["last_name"], row["first_name"], row["middle_name"]]
    return " ".join([p for p in parts if p])


# ---------- Pages ----------
@app.get("/")
def index():
    rows = db_all(
        """
        SELECT u.id, u.last_name, u.first_name, u.middle_name, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        ORDER BY u.created_at DESC, u.id DESC
        """
    )
    users = []
    for r in rows:
        users.append(
            {
                "id": r["id"],
                "fio": fio_from_row(r),
                "role_name": r["role_name"],
            }
        )
    return render_template("users.html", users=users)


@app.get("/users/<int:user_id>")
def user_view(user_id: int):
    row = db_one(
        """
        SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        """,
        (user_id,),
    )
    if not row:
        abort(404)
    user = {
        "id": row["id"],
        "login": row["login"],
        "last_name": row["last_name"],
        "first_name": row["first_name"],
        "middle_name": row["middle_name"],
        "role_name": row["role_name"],
    }
    return render_template("user_view.html", user=user)


@app.route("/users/create", methods=["GET", "POST"])
@login_required
def user_create():
    roles = roles_list()
    form = {"login": "", "password": "", "last_name": "", "first_name": "", "middle_name": "", "role_id": ""}
    errors: dict[str, str] = {}

    if request.method == "POST":
        form = {
            "login": request.form.get("login", "").strip(),
            "password": request.form.get("password", ""),
            "last_name": request.form.get("last_name", "").strip(),
            "first_name": request.form.get("first_name", "").strip(),
            "middle_name": request.form.get("middle_name", "").strip(),
            "role_id": request.form.get("role_id", "").strip(),
        }

        e = validate_login(form["login"])
        if e:
            errors["login"] = e

        pw_errors = validate_password(form["password"])
        if pw_errors:
            errors["password"] = pw_errors[0]

        e = validate_required(form["last_name"])
        if e:
            errors["last_name"] = e

        e = validate_required(form["first_name"])
        if e:
            errors["first_name"] = e

        if errors:
            flash("Исправьте ошибки в форме.", "danger")
            return render_template("user_create.html", roles=roles, form=form, errors=errors)

        role_id = int(form["role_id"]) if form["role_id"] else None

        try:
            db_exec(
                """
                INSERT INTO users(login, password_hash, last_name, first_name, middle_name, role_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    form["login"],
                    generate_password_hash(form["password"]),
                    form["last_name"],
                    form["first_name"],
                    form["middle_name"] or None,
                    role_id,
                ),
            )
        except sqlite3.IntegrityError:
            flash("Ошибка записи в БД: возможно, логин уже занят.", "danger")
            errors["login"] = "Логин уже занят."
            return render_template("user_create.html", roles=roles, form=form, errors=errors)
        except Exception:
            flash("Ошибка записи в БД.", "danger")
            return render_template("user_create.html", roles=roles, form=form, errors=errors)

        flash("Пользователь успешно создан.", "success")
        return redirect(url_for("index"))

    return render_template("user_create.html", roles=roles, form=form, errors=errors)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def user_edit(user_id: int):
    roles = roles_list()
    row = db_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not row:
        abort(404)

    form = {
        "last_name": row["last_name"],
        "first_name": row["first_name"],
        "middle_name": row["middle_name"] or "",
        "role_id": str(row["role_id"] or ""),
    }
    errors: dict[str, str] = {}

    if request.method == "POST":
        form = {
            "last_name": request.form.get("last_name", "").strip(),
            "first_name": request.form.get("first_name", "").strip(),
            "middle_name": request.form.get("middle_name", "").strip(),
            "role_id": request.form.get("role_id", "").strip(),
        }

        e = validate_required(form["last_name"])
        if e:
            errors["last_name"] = e

        e = validate_required(form["first_name"])
        if e:
            errors["first_name"] = e

        if errors:
            flash("Исправьте ошибки в форме.", "danger")
            return render_template("user_edit.html", roles=roles, form=form, errors=errors, user_id=user_id)

        role_id = int(form["role_id"]) if form["role_id"] else None

        try:
            db_exec(
                """
                UPDATE users
                SET last_name=?, first_name=?, middle_name=?, role_id=?
                WHERE id=?
                """,
                (
                    form["last_name"],
                    form["first_name"],
                    form["middle_name"] or None,
                    role_id,
                    user_id,
                ),
            )
        except Exception:
            flash("Ошибка записи в БД.", "danger")
            return render_template("user_edit.html", roles=roles, form=form, errors=errors, user_id=user_id)

        flash("Пользователь успешно обновлён.", "success")
        return redirect(url_for("index"))

    return render_template("user_edit.html", roles=roles, form=form, errors=errors, user_id=user_id)


@app.post("/users/<int:user_id>/delete")
@login_required
def user_delete(user_id: int):
    row = db_one("SELECT id, last_name, first_name, middle_name FROM users WHERE id=?", (user_id,))
    if not row:
        abort(404)

    fio = fio_from_row(row)

    try:
        db_exec("DELETE FROM users WHERE id=?", (user_id,))
    except Exception:
        flash("Ошибка удаления пользователя.", "danger")
        return redirect(url_for("index"))

    flash(f"Пользователь удалён: {fio}", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        login_value = request.form.get("login", "").strip()
        password_value = request.form.get("password", "")

        row = db_one("SELECT id, login, password_hash FROM users WHERE login = ?", (login_value,))
        if row and check_password_hash(row["password_hash"], password_value):
            login_user(User(row["id"], row["login"]))
            flash("Вход выполнен успешно.", "success")

            next_page = request.args.get("next")
            if next_page and is_safe_url(next_page):
                return redirect(next_page)

            return redirect(url_for("index"))

        flash("Неверно введены логин или пароль.", "danger")

    return render_template("login.html")


@app.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))


@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    errors: dict[str, str] = {}
    form = {"old_password": "", "new_password": "", "new_password2": ""}

    if request.method == "POST":
        form = {
            "old_password": request.form.get("old_password", ""),
            "new_password": request.form.get("new_password", ""),
            "new_password2": request.form.get("new_password2", ""),
        }

        row = db_one("SELECT password_hash FROM users WHERE id=?", (current_user.id,))
        if not row or not check_password_hash(row["password_hash"], form["old_password"]):
            errors["old_password"] = "Старый пароль введён неверно."

        pw_errors = validate_password(form["new_password"])
        if pw_errors:
            errors["new_password"] = pw_errors[0]

        if form["new_password"] != form["new_password2"]:
            errors["new_password2"] = "Пароли не совпадают."

        if errors:
            flash("Не удалось изменить пароль.", "danger")
            return render_template("password.html", form=form, errors=errors)

        try:
            db_exec(
                "UPDATE users SET password_hash=? WHERE id=?",
                (generate_password_hash(form["new_password"]), current_user.id),
            )
        except Exception:
            flash("Ошибка записи в БД.", "danger")
            return render_template("password.html", form=form, errors=errors)

        flash("Пароль успешно изменён.", "success")
        return redirect(url_for("index"))

    return render_template("password.html", form=form, errors=errors)
