from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-ostapenko-241-327"  # нужно для session и Flask-Login


# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = (
    "Для доступа к запрашиваемой странице необходимо пройти процедуру аутентификации."
)
login_manager.login_message_category = "warning"


# --- In-memory user ---
USERS = {
    "user": {"id": "user", "password": "qwerty"},
}


class User(UserMixin):
    def __init__(self, user_id: str):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id: str):
    if user_id in USERS:
        return User(user_id)
    return None


def is_safe_url(target: str) -> bool:
    # защита от редиректа на чужие сайты
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# --- Routes ---
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/counter")
def counter():
    # Счётчик посещений через session
    visits = session.get("counter_visits", 0) + 1
    session["counter_visits"] = visits
    return render_template("counter.html", visits=visits)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        login_value = request.form.get("login", "").strip()
        password_value = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user_data = USERS.get(login_value)
        if user_data and user_data["password"] == password_value:
            login_user(User(login_value), remember=remember)
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


@app.get("/secret")
@login_required
def secret():
    return render_template("secret.html")
