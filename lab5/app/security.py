from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
from db import get_db

ADMIN = "Администратор"
USER = "Пользователь"

ADMIN_RIGHTS = {
    "users.create",
    "users.edit",
    "users.view",
    "users.delete",
    "visits.view",
}

USER_RIGHTS = {
    "users.edit",
    "users.view",
    "visits.view",
}


def current_role_name() -> str | None:
    if not current_user.is_authenticated:
        return None
    row = get_db().execute(
        """
        SELECT r.name AS role_name
        FROM users u
        LEFT JOIN roles r ON r.id = u.role_id
        WHERE u.id = ?
        """,
        (int(current_user.id),),
    ).fetchone()
    return row["role_name"] if row else None


def is_admin() -> bool:
    return current_role_name() == ADMIN


def has_right(action: str, **kwargs) -> bool:
    if not current_user.is_authenticated:
        return False

    role = current_role_name()

    if role == ADMIN:
        return action in ADMIN_RIGHTS

    if role == USER:
        if action not in USER_RIGHTS:
            return False

        # object-level: user может смотреть/редактировать ТОЛЬКО себя
        if action in ("users.view", "users.edit"):
            user_id = kwargs.get("user_id")
            try:
                return int(user_id) == int(current_user.id)
            except Exception:
                return False

        # журнал посещений доступен
        if action == "visits.view":
            return True

    return False


def check_rights(action: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not has_right(action, **kwargs):
                flash("У вас недостаточно прав для доступа к данной странице.", "danger")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# helpers for templates
def can_view_user(user_id: int) -> bool:
    return has_right("users.view", user_id=user_id)


def can_edit_user(user_id: int) -> bool:
    return has_right("users.edit", user_id=user_id)


def can_delete_user() -> bool:
    return has_right("users.delete")