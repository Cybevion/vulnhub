"""Access-control modules: IDOR (profile/orders), business-logic price tamper."""
from flask import Blueprint, render_template, request, session
from common import get_db, safe_mode, login_required

bp = Blueprint("access", __name__)

@bp.route("/idor/profile")
@login_required
def idor_profile():
    safe = safe_mode()
    target_id = request.args.get("id", session.get("user_id"))

    conn = get_db()
    if safe:
        # enforce: you can only see your own profile
        try:
            target_id_int = int(target_id)
        except (TypeError, ValueError):
            conn.close()
            return render_template("idor_profile.html", safe=safe, error="Invalid profile ID.", profile=None, own_id=session["user_id"], target_id=target_id)
        if target_id_int != session["user_id"]:
            conn.close()
            return render_template("idor_profile.html", safe=safe, error="Access Denied: You can only view your own profile.", profile=None, own_id=session["user_id"], target_id=target_id)
        row = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    else:
        # VULNERABLE: uses user-supplied id, no ownership check
        row = conn.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    conn.close()

    return render_template("idor_profile.html", safe=safe, profile=dict(row) if row else None,
                           target_id=target_id, own_id=session["user_id"], error=None)


@bp.route("/idor/orders")
@login_required
def idor_orders():
    safe = safe_mode()
    target_id = request.args.get("user_id", session.get("user_id"))

    conn = get_db()
    if safe:
        try:
            target_id_int = int(target_id)
        except (TypeError, ValueError):
            conn.close()
            return render_template("idor_orders.html", safe=safe, error="Invalid user ID.", orders=[], own_id=session["user_id"], target_id=target_id)
        if target_id_int != session["user_id"]:
            conn.close()
            return render_template("idor_orders.html", safe=safe, error="Access Denied.", orders=[], own_id=session["user_id"], target_id=target_id)
        orders = conn.execute("SELECT * FROM orders WHERE user_id=?", (session["user_id"],)).fetchall()
    else:
        orders = conn.execute("SELECT * FROM orders WHERE user_id=?", (target_id,)).fetchall()
    conn.close()

    return render_template("idor_orders.html", safe=safe, orders=[dict(o) for o in orders],
                           target_id=target_id, own_id=session["user_id"], error=None)

# ══════════════════════════════════════════════════════════════════════════════
# 6. CSRF
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/logic/checkout", methods=["GET","POST"])
@login_required
def logic_checkout():
    safe = safe_mode()
    message = None
    error = None

    items = [
        {"id":1, "name":"Laptop Pro", "server_price": 999.99},
        {"id":2, "name":"Wireless Mouse", "server_price": 29.99},
        {"id":3, "name":"USB Hub", "server_price": 49.99},
    ]

    if request.method == "POST":
        try:
            item_id = int(request.form.get("item_id", 0))
            quantity = int(request.form.get("quantity", 1))
            client_price = float(request.form.get("price", 0))
        except (TypeError, ValueError):
            return render_template("logic_checkout.html", safe=safe, items=items,
                                   message=None, error="Item, quantity and price must be numeric.")

        item = next((i for i in items if i["id"] == item_id), None)
        if not item:
            error = "Invalid item."
        elif safe:
            # use server-side price — ignore client price
            total = item["server_price"] * quantity
            message = f"Order placed: {item['name']} x{quantity} = ${total:.2f} [Price from server — client value ignored]"
        else:
            # VULNERABLE: trust client-supplied price
            total = client_price * quantity
            message = f"Order placed: {item['name']} x{quantity} = ${total:.2f} [Client-supplied price used — VULNERABLE!]"

    return render_template("logic_checkout.html", safe=safe, items=items, message=message, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# 15. OS COMMAND INJECTION
# ══════════════════════════════════════════════════════════════════════════════

