import re
from flask import Flask, render_template, request, make_response, url_for, redirect

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/url-params")
def url_params():
    return render_template("url_params.html", args=request.args)


@app.get("/headers")
def headers():
    # request.headers — это объект, его удобно превратить в список пар
    return render_template("headers.html", headers=list(request.headers.items()))


@app.get("/cookies")
def cookies():
    resp = make_response(render_template("cookies.html", cookies=request.cookies))
    # чтобы на странице точно были cookie — установим демо-cookie
    if "demo_cookie" not in request.cookies:
        resp.set_cookie("demo_cookie", "hello")
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    submitted = False
    login_value = ""
    password_value = ""

    if request.method == "POST":
        submitted = True
        login_value = request.form.get("login", "")
        password_value = request.form.get("password", "")

    return render_template(
        "login.html",
        submitted=submitted,
        login_value=login_value,
        password_value=password_value,
    )


_ALLOWED_PHONE_RE = re.compile(r"^[0-9\s\-\(\)\.\+]+$")


def _format_phone(digits: str) -> str:
    # digits: 10 или 11 цифр
    if len(digits) == 11:
        core = digits[1:]  # убираем первую (7 или 8)
    else:
        core = digits

    return f"8-{core[0:3]}-{core[3:6]}-{core[6:8]}-{core[8:10]}"


@app.route("/phone", methods=["GET", "POST"])
def phone():
    value = ""
    error = ""
    formatted = ""

    if request.method == "POST":
        value = request.form.get("phone", "").strip()

        # 1) проверка допустимых символов
        if not value or not _ALLOWED_PHONE_RE.match(value):
            error = "Недопустимый ввод. В номере телефона встречаются недопустимые символы."
        else:
            digits = "".join(re.findall(r"\d", value))

            compact = re.sub(r"[\s\-\(\)\.]", "", value)  # оставляем цифры и "+"
            need_len = 11 if (compact.startswith("+7") or compact.startswith("8")) else 10

            if len(digits) != need_len:
                error = "Недопустимый ввод. Неверное количество цифр."
            else:
                formatted = _format_phone(digits)

    return render_template("phone.html", value=value, error=error, formatted=formatted)