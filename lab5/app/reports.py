import csv
import io
from flask import Blueprint, render_template, request, Response
from flask_login import login_required, current_user

from db import get_db
from security import check_rights, is_admin

bp = Blueprint("reports", __name__, url_prefix="/visits")

PER_PAGE = 10


def fio_from_user_row(u) -> str:
    parts = [u["last_name"], u["first_name"], u["middle_name"]]
    return " ".join([p for p in parts if p])


@bp.get("/")
@login_required
@check_rights("visits.view")
def journal():
    page = request.args.get("page", "1")
    try:
        page = max(1, int(page))
    except Exception:
        page = 1

    where = ""
    params = []

    if not is_admin():
        where = "WHERE v.user_id = ?"
        params.append(int(current_user.id))

    total = get_db().execute(
        f"SELECT COUNT(*) AS c FROM visit_logs v {where}",
        params,
    ).fetchone()["c"]

    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, pages)
    offset = (page - 1) * PER_PAGE

    rows = get_db().execute(
        f"""
        SELECT v.id, v.path,
               strftime('%d.%m.%Y %H:%M:%S', v.created_at) AS dt,
               u.last_name, u.first_name, u.middle_name
        FROM visit_logs v
        LEFT JOIN users u ON u.id = v.user_id
        {where}
        ORDER BY v.created_at DESC, v.id DESC
        LIMIT ? OFFSET ?
        """,
        params + [PER_PAGE, offset],
    ).fetchall()

    logs = []
    for r in rows:
        if r["last_name"] is None:
            who = "Неаутентифицированный пользователь"
        else:
            who = fio_from_user_row(r)
        logs.append({"path": r["path"], "dt": r["dt"], "who": who})

    return render_template(
        "visits.html",
        logs=logs,
        page=page,
        pages=pages,
    )


@bp.get("/pages")
@login_required
@check_rights("visits.view")
def pages_report():
    where = ""
    params = []
    if not is_admin():
        where = "WHERE user_id = ?"
        params.append(int(current_user.id))

    rows = get_db().execute(
        f"""
        SELECT path, COUNT(*) AS c
        FROM visit_logs
        {where}
        GROUP BY path
        ORDER BY c DESC, path ASC
        """,
        params,
    ).fetchall()

    data = [{"path": r["path"], "count": r["c"]} for r in rows]
    return render_template("report_pages.html", data=data)


@bp.get("/pages/export")
@login_required
@check_rights("visits.view")
def pages_export():
    where = ""
    params = []
    if not is_admin():
        where = "WHERE user_id = ?"
        params.append(int(current_user.id))

    rows = get_db().execute(
        f"""
        SELECT path, COUNT(*) AS c
        FROM visit_logs
        {where}
        GROUP BY path
        ORDER BY c DESC, path ASC
        """,
        params,
    ).fetchall()

    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["Страница", "Количество посещений"])
    for r in rows:
        w.writerow([r["path"], r["c"]])

    content = "\ufeff" + out.getvalue()
    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=pages_report.csv"},
    )


@bp.get("/users")
@login_required
@check_rights("visits.view")
def users_report():
    where = ""
    params = []
    if not is_admin():
        where = "WHERE v.user_id = ?"
        params.append(int(current_user.id))

    rows = get_db().execute(
        f"""
        SELECT v.user_id,
               CASE
                 WHEN v.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                 ELSE (u.last_name || ' ' || u.first_name || CASE WHEN u.middle_name IS NOT NULL THEN ' ' || u.middle_name ELSE '' END)
               END AS who,
               COUNT(*) AS c
        FROM visit_logs v
        LEFT JOIN users u ON u.id = v.user_id
        {where}
        GROUP BY v.user_id
        ORDER BY c DESC, who ASC
        """,
        params,
    ).fetchall()

    data = [{"who": r["who"], "count": r["c"]} for r in rows]
    return render_template("report_users.html", data=data)


@bp.get("/users/export")
@login_required
@check_rights("visits.view")
def users_export():
    where = ""
    params = []
    if not is_admin():
        where = "WHERE v.user_id = ?"
        params.append(int(current_user.id))

    rows = get_db().execute(
        f"""
        SELECT v.user_id,
               CASE
                 WHEN v.user_id IS NULL THEN 'Неаутентифицированный пользователь'
                 ELSE (u.last_name || ' ' || u.first_name || CASE WHEN u.middle_name IS NOT NULL THEN ' ' || u.middle_name ELSE '' END)
               END AS who,
               COUNT(*) AS c
        FROM visit_logs v
        LEFT JOIN users u ON u.id = v.user_id
        {where}
        GROUP BY v.user_id
        ORDER BY c DESC, who ASC
        """,
        params,
    ).fetchall()

    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["Пользователь", "Количество посещений"])
    for r in rows:
        w.writerow([r["who"], r["c"]])

    content = "\ufeff" + out.getvalue()
    return Response(
        content,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=users_report.csv"},
    )