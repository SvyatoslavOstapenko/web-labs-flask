import os
import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, close_db
from security import (
    check_rights,
    has_right,
    can_view_user,
    can_edit_user,
    can_delete_user,
    is_admin,
)
from reports import bp as reports_bp

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-ostapenko-241-327"
app.config["DB_PATH"] = os.path.join(os.path.dirname(__file__), "app.db")

app.teardown_appcontext(close_db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации."
login_manager.login_message_category = "warning"

app.register_blueprint(reports_bp)

# --- validation from LR4 (оставляем) ---
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
    return get_db().execute("SELECT id, name FROM roles ORDER BY name").fetchall()


def fio_from_row(row) -> str:
    parts = [row["last_name"], row["first_name"], row["middle_name"]]
    return " ".join([p for p in parts if p])


@app.context_processor
def inject_helpers():
    return dict(
        has_right=has_right,
        can_view_user=can_view_user,
        can_edit_user=can_edit_user,
        can_delete_user=can_delete_user,
        is_admin=is_admin,
    )


# --- user model for Flask-Login ---
class User(UserMixin):
    def __init__(self, user_id: int, login: str, role_name: str | None):
        self.id = str(user_id)
        self.login = login
        self.role_name = role_name


@login_manager.user_loader
def load_user(user_id: str):
    row = get_db().execute(
        """
        SELECT u.id, u.login, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()
    if row:
        return User(row["id"], row["login"], row["role_name"])
    return None


# --- visit logging ---
@app.before_request
def log_visit():
    # не логируем статику и favicon
    if request.path.startswith("/static") or request.path == "/favicon.ico":
        return

    user_id = int(current_user.id) if current_user.is_authenticated else None

    try:
        db = get_db()
        db.execute("INSERT INTO visit_logs(path, user_id) VALUES (?, ?)", (request.path, user_id))
        db.commit()
    except sqlite3.OperationalError:
        # если БД еще не инициализирована
        pass


# --- routes ---
@app.get("/")
def index():
    rows = get_db().execute(
        """
        SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        ORDER BY u.created_at DESC, u.id DESC
        """
    ).fetchall()

    users = []
    for r in rows:
        users.append(
            {
                "id": r["id"],
                "login": r["login"],
                "fio": fio_from_row(r),
                "role_name": r["role_name"],
            }
        )
    return render_template("users.html", users=users)


@app.get("/users/<int:user_id>")
@login_required
@check_rights("users.view")
def user_view(user_id: int):
    row = get_db().execute(
        """
        SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()
    if not row:
        abort(404)

    user = dict(row)
    return render_template("user_view.html", user=user)


@app.route("/users/create", methods=["GET", "POST"])
@login_required
@check_rights("users.create")
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
            get_db().execute(
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
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("Ошибка записи в БД: возможно, логин уже занят.", "danger")
            errors["login"] = "Логин уже занят."
            return render_template("user_create.html", roles=roles, form=form, errors=errors)

        flash("Пользователь успешно создан.", "success")
        return redirect(url_for("index"))

    return render_template("user_create.html", roles=roles, form=form, errors=errors)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@check_rights("users.edit")
def user_edit(user_id: int):
    roles = roles_list()
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
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
            return render_template(
                "user_edit.html",
                roles=roles,
                form=form,
                errors=errors,
                user_id=user_id,
                role_disabled=(not is_admin()),
            )

        # если не админ — роль менять нельзя
        if not is_admin():
            role_id = row["role_id"]
        else:
            role_id = int(form["role_id"]) if form["role_id"] else None

        try:
            get_db().execute(
                """
                UPDATE users
                SET last_name=?, first_name=?, middle_name=?, role_id=?
                WHERE id=?
                """,
                (form["last_name"], form["first_name"], form["middle_name"] or None, role_id, user_id),
            )
            get_db().commit()
        except Exception:
            flash("Ошибка записи в БД.", "danger")
            return render_template(
                "user_edit.html",
                roles=roles,
                form=form,
                errors=errors,
                user_id=user_id,
                role_disabled=(not is_admin()),
            )

        flash("Пользователь успешно обновлён.", "success")
        return redirect(url_for("index"))

    return render_template(
        "user_edit.html",
        roles=roles,
        form=form,
        errors=errors,
        user_id=user_id,
        role_disabled=(not is_admin()),
    )


@app.post("/users/<int:user_id>/delete")
@login_required
@check_rights("users.delete")
def user_delete(user_id: int):
    row = get_db().execute(
        "SELECT id, last_name, first_name, middle_name FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not row:
        abort(404)

    fio = fio_from_row(row)

    try:
        get_db().execute("DELETE FROM users WHERE id=?", (user_id,))
        get_db().commit()
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

        row = get_db().execute(
            "SELECT id, login, password_hash FROM users WHERE login = ?",
            (login_value,),
        ).fetchone()

        if row and check_password_hash(row["password_hash"], password_value):
            login_user(User(row["id"], row["login"], None))
            flash("Вход выполнен успешно.", "success")
            return redirect(url_for("index"))

        flash("Неверно введены логин или пароль.", "danger")

    return render_template("login.html")


@app.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("index"))