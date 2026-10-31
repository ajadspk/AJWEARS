from flask import Flask, render_template, jsonify, request, session, redirect, url_for, abort
import sqlite3
import os
import re
import secrets
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ============================================================
# APP CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "ajwears.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ.get(
        "SECRET_KEY",
        "ajwears-development-change-me"
    ),
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    JSON_SORT_KEYS=False,
)


# ============================================================
# CONSTANTS
# ============================================================

ORDER_STATUSES = [
    "Order Placed",
    "Confirmed",
    "Processing",
    "Packed",
    "Shipped",
    "Out for Delivery",
    "Delivered",
    "Cancelled",
    "Returned",
    "Refunded",
]

ROLES = {
    "customer",
    "editor",
    "admin",
    "super_admin",
}


# ============================================================
# DATABASE
# ============================================================

def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def now():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# CSRF
# ============================================================

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)

    return session["csrf"]


def require_csrf():
    data = request.get_json(silent=True) or {}

    token = (
        request.headers.get("X-CSRF-Token")
        or data.get("_csrf")
    )

    if not token or token != session.get("csrf"):
        abort(400, description="Invalid CSRF token")


# ============================================================
# CURRENT USER
# ============================================================

def current_user():
    uid = session.get("user_id")

    if not uid:
        return None

    con = get_db()

    row = con.execute(
        """
        SELECT
            id,
            name,
            email,
            phone,
            role,
            active,
            created_at
        FROM users
        WHERE id=?
        """,
        (uid,)
    ).fetchone()

    con.close()

    if not row or not row["active"]:
        session.clear()
        return None

    return dict(row)


# ============================================================
# LOGIN REQUIRED
# ============================================================

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):

        user = current_user()

        if not user:
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Authentication required"
                }), 401

            return redirect(
                url_for(
                    "login_page",
                    next=request.path
                )
            )

        return fn(*args, **kwargs)

    return wrapped


# ============================================================
# ROLE REQUIRED
# ============================================================

def role_required(*roles):

    def deco(fn):

        @wraps(fn)
        def wrapped(*args, **kwargs):

            user = current_user()

            # User is not logged in
            if not user:

                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Authentication required"
                    }), 401

                return redirect(
                    url_for(
                        "login_page",
                        next=request.path
                    )
                )

            # User is logged in but has no required role
            if user.get("role") not in roles:

                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Admin permission required",
                        "current_role": user.get("role"),
                        "required_roles": list(roles)
                    }), 403

                return jsonify({
                    "error": "Admin permission required",
                    "current_role": user.get("role")
                }), 403

            return fn(*args, **kwargs)

        return wrapped

    return deco


# ============================================================
# PUBLIC PRODUCT FORMAT
# ============================================================

def public_product(row):

    d = dict(row)

    d["featured"] = bool(
        d.get("featured")
    )

    d["active"] = bool(
        d.get("active", 1)
    )

    d["colors"] = [
        x.strip()
        for x in (d.get("colors") or "").split(",")
        if x.strip()
    ]

    d["sizes"] = [
        x.strip()
        for x in (
            d.get("sizes") or "S,M,L,XL"
        ).split(",")
        if x.strip()
    ]

    return d


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    con = get_db()

    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS addresses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            province TEXT DEFAULT '',
            postal_code TEXT DEFAULT '',
            country TEXT DEFAULT 'Pakistan',
            is_default INTEGER DEFAULT 0,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            collection TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            sale_price INTEGER,
            image TEXT NOT NULL,
            badge TEXT DEFAULT '',
            stock INTEGER DEFAULT 0,
            featured INTEGER DEFAULT 1,
            active INTEGER DEFAULT 1,
            sku TEXT DEFAULT '',
            colors TEXT DEFAULT '',
            sizes TEXT DEFAULT 'S,M,L,XL',
            material TEXT DEFAULT '',
            care TEXT DEFAULT '',
            seo_title TEXT DEFAULT '',
            seo_description TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS product_images(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            image TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY(product_id)
                REFERENCES products(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS collections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            image TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS categories(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            image TEXT DEFAULT '',
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS carts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            session_key TEXT UNIQUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cart_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cart_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            size TEXT DEFAULT 'M',
            color TEXT DEFAULT '',
            quantity INTEGER NOT NULL,
            FOREIGN KEY(cart_id)
                REFERENCES carts(id)
                ON DELETE CASCADE,
            FOREIGN KEY(product_id)
                REFERENCES products(id)
                ON DELETE CASCADE,
            UNIQUE(cart_id, product_id, size, color)
        );

        CREATE TABLE IF NOT EXISTS wishlists(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            FOREIGN KEY(product_id)
                REFERENCES products(id)
                ON DELETE CASCADE,
            UNIQUE(user_id, product_id)
        );

        CREATE TABLE IF NOT EXISTS orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            customer_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            province TEXT DEFAULT '',
            postal_code TEXT DEFAULT '',
            payment TEXT NOT NULL,
            subtotal INTEGER NOT NULL DEFAULT 0,
            shipping INTEGER NOT NULL DEFAULT 0,
            discount INTEGER NOT NULL DEFAULT 0,
            total INTEGER NOT NULL,
            status TEXT DEFAULT 'Order Placed',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS order_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price INTEGER NOT NULL,
            size TEXT NOT NULL,
            color TEXT DEFAULT '',
            FOREIGN KEY(order_id)
                REFERENCES orders(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS order_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            note TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(order_id)
                REFERENCES orders(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS newsletter(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS coupons(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            kind TEXT NOT NULL,
            value INTEGER NOT NULL,
            min_order INTEGER DEFAULT 0,
            expires_at TEXT DEFAULT '',
            usage_limit INTEGER DEFAULT 0,
            used_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS site_settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS homepage_sections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section_key TEXT UNIQUE NOT NULL,
            title TEXT DEFAULT '',
            subtitle TEXT DEFAULT '',
            image TEXT DEFAULT '',
            cta TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            sort_order INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS admin_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            entity TEXT,
            entity_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE SET NULL
        );
        """
    )

    # ========================================================
    # MIGRATE PRODUCTS
    # ========================================================

    cols = {
        r["name"]
        for r in con.execute(
            "PRAGMA table_info(products)"
        ).fetchall()
    }

    additions = {
        "active": "INTEGER DEFAULT 1",
        "sku": "TEXT DEFAULT ''",
        "colors": "TEXT DEFAULT ''",
        "sizes": "TEXT DEFAULT 'S,M,L,XL'",
        "material": "TEXT DEFAULT ''",
        "care": "TEXT DEFAULT ''",
        "seo_title": "TEXT DEFAULT ''",
        "seo_description": "TEXT DEFAULT ''",
    }

    for column, column_type in additions.items():

        if column not in cols:

            con.execute(
                f"""
                ALTER TABLE products
                ADD COLUMN {column} {column_type}
                """
            )

    # ========================================================
    # MIGRATE ORDERS
    # ========================================================

    order_cols = {
        r["name"]
        for r in con.execute(
            "PRAGMA table_info(orders)"
        ).fetchall()
    }

    order_additions = {
        "user_id": "INTEGER",
        "province": "TEXT DEFAULT ''",
        "postal_code": "TEXT DEFAULT ''",
        "subtotal": "INTEGER DEFAULT 0",
        "shipping": "INTEGER DEFAULT 0",
        "discount": "INTEGER DEFAULT 0",
    }

    for column, column_type in order_additions.items():

        if column not in order_cols:

            con.execute(
                f"""
                ALTER TABLE orders
                ADD COLUMN {column} {column_type}
                """
            )

    # ========================================================
    # MIGRATE ORDER ITEMS
    # ========================================================

    item_cols = {
        r["name"]
        for r in con.execute(
            "PRAGMA table_info(order_items)"
        ).fetchall()
    }

    if "color" not in item_cols:

        con.execute(
            """
            ALTER TABLE order_items
            ADD COLUMN color TEXT DEFAULT ''
            """
        )

    # ========================================================
    # SEED PRODUCTS
    # ========================================================

    product_count = con.execute(
        "SELECT COUNT(*) FROM products"
    ).fetchone()[0]

    if product_count == 0:

        products = [

            (
                "AJ Signature Overshirt",
                "Men",
                "Men's Collection",
                "A relaxed premium layer built around the AJWEARS everyday silhouette.",
                7490,
                6790,
                "/static/assets/05_Mens_collection_exact.png",
                "NEW",
                18,
                1,
                "AJ-OS-001",
                "Black,Stone",
                "S,M,L,XL",
                "Cotton blend"
            ),

            (
                "Aurelia Essential Hoodie",
                "Women",
                "Women's Collection",
                "Soft oversized fleece with a clean, modern luxury profile.",
                6990,
                None,
                "/static/assets/06_Womens_collection_exact.png",
                "NEW",
                16,
                1,
                "AJ-HO-002",
                "Ivory,Black",
                "S,M,L,XL",
                "Premium fleece"
            ),

            (
                "Cloudline Everyday Set",
                "Women",
                "New Arrivals",
                "A tonal wardrobe set designed for effortless everyday styling.",
                8990,
                None,
                "/static/assets/07_New_arrivals_exact.png",
                "NEW",
                12,
                1,
                "AJ-SET-003",
                "Cloud,Black",
                "S,M,L",
                "Cotton"
            ),

            (
                "Core Fleece Hoodie",
                "Unisex",
                "Essentials",
                "A premium everyday essential with a soft structured drape.",
                5990,
                None,
                "/static/assets/08_Essentials_exact.png",
                "ESSENTIAL",
                22,
                1,
                "AJ-HO-004",
                "Black,Grey",
                "S,M,L,XL,XXL",
                "Fleece"
            ),

            (
                "Noir Graphic Streetwear",
                "Men",
                "Streetwear",
                "A statement streetwear layer with a confident oversized attitude.",
                7990,
                6990,
                "/static/assets/09_Streetwear_exact.png",
                "SALE",
                11,
                1,
                "AJ-ST-005",
                "Black",
                "S,M,L,XL",
                "Cotton"
            ),

            (
                "AJ Signature Cap",
                "Accessories",
                "Accessories",
                "Minimal cotton cap finished with understated AJWEARS identity.",
                2490,
                None,
                "/static/assets/10_Accessories_exact.png",
                "NEW",
                25,
                1,
                "AJ-CP-006",
                "Black,Stone",
                "One Size",
                "Cotton"
            ),

            (
                "Statement Bomber",
                "Men",
                "Men's Collection",
                "A clean contemporary outer layer designed for day-to-night wear.",
                10990,
                9490,
                "/static/assets/05_Mens_collection_exact.png",
                "SALE",
                8,
                1,
                "AJ-BM-007",
                "Black,Olive",
                "S,M,L,XL",
                "Nylon"
            ),

            (
                "Soft Rose Hoodie",
                "Women",
                "Women's Collection",
                "Relaxed premium hoodie with a soft seasonal colour story.",
                6290,
                None,
                "/static/assets/06_Womens_collection_exact.png",
                "",
                15,
                1,
                "AJ-HO-008",
                "Rose,Black",
                "S,M,L,XL",
                "Fleece"
            ),

            (
                "Ivory New Season Layer",
                "Unisex",
                "New Arrivals",
                "Fresh seasonal styling with a refined neutral palette.",
                7390,
                None,
                "/static/assets/07_New_arrivals_exact.png",
                "NEW",
                13,
                1,
                "AJ-LY-009",
                "Ivory",
                "S,M,L,XL",
                "Cotton"
            ),

            (
                "Essential Neutral Layer",
                "Unisex",
                "Essentials",
                "A quiet, versatile layer made for repeat wear.",
                5490,
                None,
                "/static/assets/08_Essentials_exact.png",
                "ESSENTIAL",
                20,
                1,
                "AJ-LY-010",
                "Beige,Grey",
                "S,M,L,XL",
                "Cotton"
            ),

            (
                "Urban Black Hoodie",
                "Men",
                "Streetwear",
                "A bold black layer inspired by the AJWEARS streetwear edit.",
                7290,
                None,
                "/static/assets/09_Streetwear_exact.png",
                "",
                14,
                1,
                "AJ-HO-011",
                "Black",
                "S,M,L,XL",
                "Cotton"
            ),

            (
                "AJ Black Cap + Shades",
                "Accessories",
                "Accessories",
                "A signature finishing piece for a complete everyday look.",
                2990,
                None,
                "/static/assets/10_Accessories_exact.png",
                "",
                17,
                1,
                "AJ-AC-012",
                "Black",
                "One Size",
                "Cotton"
            ),
        ]

        con.executemany(
            """
            INSERT INTO products(
                name,
                category,
                collection,
                description,
                price,
                sale_price,
                image,
                badge,
                stock,
                featured,
                sku,
                colors,
                sizes,
                material
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            products
        )

    # ========================================================
    # SITE SETTINGS
    # ========================================================

    defaults = {
        "brand_name": "AJWEARS",
        "announcement": "FREE DELIVERY ON ORDERS OVER PKR 8,000  •  EASY RETURNS",
        "currency": "PKR",
        "contact_email": "hello@ajwears.com",
        "phone": "",
        "instagram": "#",
        "tiktok": "#",
        "youtube": "#",
    }

    for key, value in defaults.items():

        con.execute(
            """
            INSERT OR IGNORE INTO site_settings(key,value)
            VALUES(?,?)
            """,
            (key, value)
        )

    # ========================================================
    # CATEGORIES
    # ========================================================

    for name in [
        "Men",
        "Women",
        "Unisex",
        "Accessories"
    ]:

        slug = re.sub(
            r"[^a-z0-9]+",
            "-",
            name.lower()
        ).strip("-")

        con.execute(
            """
            INSERT OR IGNORE INTO categories(name,slug)
            VALUES(?,?)
            """,
            (name, slug)
        )

    # ========================================================
    # COLLECTIONS
    # ========================================================

    for name in [
        "Men's Collection",
        "Women's Collection",
        "New Arrivals",
        "Essentials",
        "Streetwear",
        "Accessories"
    ]:

        slug = re.sub(
            r"[^a-z0-9]+",
            "-",
            name.lower()
        ).strip("-")

        con.execute(
            """
            INSERT OR IGNORE INTO collections(name,slug)
            VALUES(?,?)
            """,
            (name, slug)
        )

    # ========================================================
    # ADMIN ACCOUNT
    #
    # IMPORTANT FIX:
    # If ADMIN_EMAIL already exists as customer,
    # it will automatically become super_admin.
    # ========================================================

    admin_email = os.environ.get(
        "ADMIN_EMAIL",
        ""
    ).strip().lower()

    admin_password = os.environ.get(
        "ADMIN_PASSWORD",
        ""
    )

    if admin_email and admin_password:

        existing_admin = con.execute(
            """
            SELECT id
            FROM users
            WHERE email=?
            """,
            (admin_email,)
        ).fetchone()

        hashed_admin_password = generate_password_hash(
            admin_password
        )

        if existing_admin:

            con.execute(
                """
                UPDATE users
                SET
                    role='super_admin',
                    active=1,
                    password_hash=?
                WHERE email=?
                """,
                (
                    hashed_admin_password,
                    admin_email
                )
            )

        else:

            con.execute(
                """
                INSERT INTO users(
                    name,
                    email,
                    password_hash,
                    role,
                    active
                )
                VALUES(
                    ?,
                    ?,
                    ?,
                    'super_admin',
                    1
                )
                """,
                (
                    "AJWEARS Admin",
                    admin_email,
                    hashed_admin_password
                )
            )

    con.commit()
    con.close()


# ============================================================
# SETTINGS
# ============================================================

def get_settings():

    con = get_db()

    rows = con.execute(
        "SELECT key,value FROM site_settings"
    ).fetchall()

    con.close()

    return {
        r["key"]: r["value"]
        for r in rows
    }


# ============================================================
# CART
# ============================================================

def get_cart(user=None):

    con = get_db()

    if user:

        row = con.execute(
            """
            SELECT *
            FROM carts
            WHERE user_id=?
            """,
            (user["id"],)
        ).fetchone()

    else:

        session_key = session.get(
            "guest_cart_key"
        )

        row = (
            con.execute(
                """
                SELECT *
                FROM carts
                WHERE session_key=?
                """,
                (session_key,)
            ).fetchone()
            if session_key
            else None
        )

    if not row:

        if user:

            con.execute(
                """
                INSERT INTO carts(user_id)
                VALUES(?)
                """,
                (user["id"],)
            )

        else:

            key = secrets.token_urlsafe(18)

            session["guest_cart_key"] = key

            con.execute(
                """
                INSERT INTO carts(session_key)
                VALUES(?)
                """,
                (key,)
            )

        cid = con.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]

    else:

        cid = row["id"]

    rows = con.execute(
        """
        SELECT
            ci.id,
            ci.product_id,
            ci.size,
            ci.color,
            ci.quantity,
            p.name,
            p.image,
            p.price,
            p.sale_price,
            p.stock,
            p.sizes,
            p.colors
        FROM cart_items ci
        JOIN products p
            ON p.id=ci.product_id
        WHERE ci.cart_id=?
        """,
        (cid,)
    ).fetchall()

    con.close()

    items = []

    for row in rows:

        d = dict(row)

        d["price"] = (
            row["sale_price"]
            if row["sale_price"] is not None
            else row["price"]
        )

        items.append(d)

    return items


def cart_id_for(user):

    con = get_db()

    if user:

        row = con.execute(
            """
            SELECT id
            FROM carts
            WHERE user_id=?
            """,
            (user["id"],)
        ).fetchone()

    else:

        session_key = session.get(
            "guest_cart_key"
        )

        row = (
            con.execute(
                """
                SELECT id
                FROM carts
                WHERE session_key=?
                """,
                (session_key,)
            ).fetchone()
            if session_key
            else None
        )

    if row:

        cid = row["id"]

    else:

        if user:

            con.execute(
                """
                INSERT INTO carts(user_id)
                VALUES(?)
                """,
                (user["id"],)
            )

        else:

            key = secrets.token_urlsafe(18)

            session["guest_cart_key"] = key

            con.execute(
                """
                INSERT INTO carts(session_key)
                VALUES(?)
                """,
                (key,)
            )

        cid = con.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]

    con.commit()
    con.close()

    return cid


# ============================================================
# ADMIN LOG
# ============================================================

def log_admin(
    user,
    action,
    entity="",
    entity_id=None
):

    if not user:
        return

    con = get_db()

    con.execute(
        """
        INSERT INTO admin_logs(
            user_id,
            action,
            entity,
            entity_id
        )
        VALUES(?,?,?,?)
        """,
        (
            user["id"],
            action,
            entity,
            entity_id
        )
    )

    con.commit()
    con.close()


# ============================================================
# CONTEXT PROCESSOR
# ============================================================

@app.context_processor
def inject():

    return {
        "user": current_user(),
        "settings": get_settings(),
        "csrf": csrf_token(),
    }


# ============================================================
# FRONTEND PAGES
# ============================================================

@app.get("/")
def home():
    return render_template("index.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/register")
def register_page():
    return render_template("register.html")


@app.get("/account")
@login_required
def account_page():
    return render_template("account.html")


# ============================================================
# ADMIN PAGE
# ============================================================

@app.get("/admin")
@login_required
def admin_page():

    user = current_user()

    if not user:
        return redirect(
            url_for(
                "login_page",
                next="/admin"
            )
        )

    if user.get("role") not in {
        "admin",
        "editor",
        "super_admin"
    }:

        return jsonify({
            "error": "Admin permission required",
            "current_role": user.get("role")
        }), 403

    return render_template("admin.html")


# ============================================================
# AUTH
# ============================================================

@app.get("/api/me")
def api_me():

    return jsonify({
        "user": current_user()
    })


@app.post("/api/auth/register")
def register():

    data = request.get_json(
        silent=True
    ) or {}

    name = str(
        data.get("name", "")
    ).strip()

    email = str(
        data.get("email", "")
    ).strip().lower()

    phone = str(
        data.get("phone", "")
    ).strip()

    password = str(
        data.get("password", "")
    )

    if (
        len(name) < 2
        or "@" not in email
        or len(password) < 8
    ):

        return jsonify({
            "error": (
                "Enter a valid name, email "
                "and password of at least "
                "8 characters."
            )
        }), 400

    con = get_db()

    try:

        cur = con.execute(
            """
            INSERT INTO users(
                name,
                email,
                phone,
                password_hash,
                role
            )
            VALUES(?,?,?,?,?)
            """,
            (
                name,
                email,
                phone,
                generate_password_hash(password),
                "customer"
            )
        )

        uid = cur.lastrowid

        con.execute(
            """
            INSERT INTO carts(user_id)
            VALUES(?)
            """,
            (uid,)
        )

        con.commit()

    except sqlite3.IntegrityError:

        con.close()

        return jsonify({
            "error": (
                "An account with this "
                "email already exists."
            )
        }), 409

    con.close()

    session["user_id"] = uid
    session["csrf"] = secrets.token_urlsafe(24)

    return jsonify({
        "ok": True,
        "user": current_user()
    })


@app.post("/api/auth/login")
def login():

    data = request.get_json(
        silent=True
    ) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    password = str(
        data.get("password", "")
    )

    con = get_db()

    row = con.execute(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (email,)
    ).fetchone()

    con.close()

    if (
        not row
        or not row["active"]
        or not check_password_hash(
            row["password_hash"],
            password
        )
    ):

        return jsonify({
            "error": "Invalid email or password."
        }), 401

    session.clear()

    session["user_id"] = row["id"]
    session["csrf"] = secrets.token_urlsafe(24)

    return jsonify({
        "ok": True,
        "user": current_user()
    })


@app.post("/api/auth/logout")
def logout():

    session.clear()

    return jsonify({
        "ok": True
    })


# ============================================================
# NEWSLETTER
# ============================================================

@app.post("/api/newsletter")
def newsletter_api():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    email = str(
        data.get("email", "")
    ).strip().lower()

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):

        return jsonify({
            "error": (
                "Please enter a valid "
                "email address."
            )
        }), 400

    con = get_db()

    con.execute(
        """
        INSERT OR IGNORE INTO newsletter(email)
        VALUES(?)
        """,
        (email,)
    )

    con.commit()
    con.close()

    return jsonify({
        "ok": True,
        "message": "You're on the AJWEARS list."
    })


# ============================================================
# PRODUCTS
# ============================================================

@app.get("/api/products")
def products_api():

    con = get_db()

    rows = con.execute(
        """
        SELECT *
        FROM products
        WHERE active=1
        ORDER BY featured DESC, id DESC
        """
    ).fetchall()

    con.close()

    return jsonify([
        public_product(row)
        for row in rows
    ])


@app.get("/api/products/<int:pid>")
def product_api(pid):

    con = get_db()

    row = con.execute(
        """
        SELECT *
        FROM products
        WHERE id=? AND active=1
        """,
        (pid,)
    ).fetchone()

    images = con.execute(
        """
        SELECT image
        FROM product_images
        WHERE product_id=?
        ORDER BY sort_order,id
        """,
        (pid,)
    ).fetchall()

    con.close()

    if not row:

        return jsonify({
            "error": "Product not found"
        }), 404

    d = public_product(row)

    d["gallery"] = (
        [d["image"]]
        + [x["image"] for x in images]
    )

    return jsonify(d)


# ============================================================
# CART API
# ============================================================

@app.get("/api/cart")
def api_cart():

    items = get_cart(
        current_user()
    )

    return jsonify({
        "items": items,
        "count": sum(
            x["quantity"]
            for x in items
        ),
        "total": sum(
            x["price"] * x["quantity"]
            for x in items
        )
    })


@app.post("/api/cart/items")
def add_cart():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    try:
        pid = int(
            data.get("product_id", 0)
        )

        qty = max(
            1,
            min(
                int(data.get("quantity", 1)),
                20
            )
        )

    except (TypeError, ValueError):

        return jsonify({
            "error": "Invalid product or quantity."
        }), 400

    size = str(
        data.get("size", "M")
    )

    color = str(
        data.get("color", "")
    )

    con = get_db()

    product = con.execute(
        """
        SELECT *
        FROM products
        WHERE id=? AND active=1
        """,
        (pid,)
    ).fetchone()

    if not product:

        con.close()

        return jsonify({
            "error": "Product not found"
        }), 404

    sizes = [
        x.strip()
        for x in (
            product["sizes"]
            or "S,M,L,XL"
        ).split(",")
        if x.strip()
    ]

    colors = [
        x.strip()
        for x in (
            product["colors"]
            or ""
        ).split(",")
        if x.strip()
    ]

    if sizes and size not in sizes:

        con.close()

        return jsonify({
            "error": "Please select a valid size."
        }), 400

    if colors and color not in colors:

        con.close()

        return jsonify({
            "error": "Please select a valid color."
        }), 400

    if qty > product["stock"]:

        con.close()

        return jsonify({
            "error": "Not enough stock available."
        }), 400

    cid = cart_id_for(
        current_user()
    )

    row = con.execute(
        """
        SELECT *
        FROM cart_items
        WHERE
            cart_id=?
            AND product_id=?
            AND size=?
            AND color=?
        """,
        (
            cid,
            pid,
            size,
            color
        )
    ).fetchone()

    if row:

        con.execute(
            """
            UPDATE cart_items
            SET quantity=MIN(?, quantity+?)
            WHERE id=?
            """,
            (
                product["stock"],
                qty,
                row["id"]
            )
        )

    else:

        con.execute(
            """
            INSERT INTO cart_items(
                cart_id,
                product_id,
                size,
                color,
                quantity
            )
            VALUES(?,?,?,?,?)
            """,
            (
                cid,
                pid,
                size,
                color,
                qty
            )
        )

    con.commit()
    con.close()

    return api_cart()


@app.patch("/api/cart/items/<int:item_id>")
def update_cart(item_id):

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    try:
        qty = int(
            data.get("quantity", 1)
        )

    except (TypeError, ValueError):

        return jsonify({
            "error": "Invalid quantity."
        }), 400

    con = get_db()

    user = current_user()

    cid = cart_id_for(user)

    row = con.execute(
        """
        SELECT
            ci.*,
            p.stock
        FROM cart_items ci
        JOIN products p
            ON p.id=ci.product_id
        WHERE
            ci.id=?
            AND ci.cart_id=?
        """,
        (
            item_id,
            cid
        )
    ).fetchone()

    if not row:

        con.close()

        return jsonify({
            "error": "Cart item not found"
        }), 404

    if qty <= 0:

        con.execute(
            """
            DELETE FROM cart_items
            WHERE id=?
            """,
            (item_id,)
        )

    else:

        con.execute(
            """
            UPDATE cart_items
            SET quantity=?
            WHERE id=?
            """,
            (
                min(
                    qty,
                    row["stock"]
                ),
                item_id
            )
        )

    con.commit()
    con.close()

    return api_cart()


@app.delete("/api/cart/items/<int:item_id>")
def delete_cart(item_id):

    require_csrf()

    con = get_db()

    cid = cart_id_for(
        current_user()
    )

    con.execute(
        """
        DELETE FROM cart_items
        WHERE id=? AND cart_id=?
        """,
        (
            item_id,
            cid
        )
    )

    con.commit()
    con.close()

    return api_cart()


# ============================================================
# WISHLIST
# ============================================================

@app.get("/api/wishlist")
@login_required
def wishlist_api():

    con = get_db()

    rows = con.execute(
        """
        SELECT p.*
        FROM wishlists w
        JOIN products p
            ON p.id=w.product_id
        WHERE w.user_id=?
        ORDER BY w.created_at DESC
        """,
        (
            current_user()["id"],
        )
    ).fetchall()

    con.close()

    return jsonify([
        public_product(row)
        for row in rows
    ])


@app.post("/api/wishlist/<int:pid>")
@login_required
def wish_add(pid):

    require_csrf()

    con = get_db()

    exists = con.execute(
        """
        SELECT id
        FROM products
        WHERE id=?
        """,
        (pid,)
    ).fetchone()

    if not exists:

        con.close()

        return jsonify({
            "error": "Product not found"
        }), 404

    con.execute(
        """
        INSERT OR IGNORE INTO wishlists(
            user_id,
            product_id
        )
        VALUES(?,?)
        """,
        (
            current_user()["id"],
            pid
        )
    )

    con.commit()
    con.close()

    return jsonify({
        "ok": True
    })


@app.delete("/api/wishlist/<int:pid>")
@login_required
def wish_delete(pid):

    require_csrf()

    con = get_db()

    con.execute(
        """
        DELETE FROM wishlists
        WHERE
            user_id=?
            AND product_id=?
        """,
        (
            current_user()["id"],
            pid
        )
    )

    con.commit()
    con.close()

    return jsonify({
        "ok": True
    })


# ============================================================
# ORDERS
# ============================================================

@app.post("/api/orders")
def create_order():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    user = current_user()

    customer = data.get(
        "customer"
    ) or {}

    items = data.get(
        "items"
    ) or []

    if user:

        items = get_cart(user)

        customer = {
            **customer,
            "name": user["name"],
            "email": user["email"],
            "phone": (
                customer.get("phone")
                or user.get("phone", "")
            )
        }

    if not items:

        return jsonify({
            "error": "Your bag is empty."
        }), 400

    required = (
        "name",
        "email",
        "phone",
        "address",
        "city"
    )

    if not all(
        str(customer.get(key, "")).strip()
        for key in required
    ):

        return jsonify({
            "error": (
                "Please complete all "
                "checkout fields."
            )
        }), 400

    payment = str(
        data.get(
            "payment",
            "Cash on Delivery"
        )
    )

    if payment not in {
        "Cash on Delivery",
        "Bank Transfer"
    }:

        payment = "Cash on Delivery"

    con = get_db()

    try:

        verified = []
        subtotal = 0

        for item in items:

            try:

                pid = int(
                    item.get(
                        "product_id",
                        item.get("id", 0)
                    )
                )

                qty = max(
                    1,
                    min(
                        int(
                            item.get(
                                "quantity",
                                item.get("qty", 1)
                            )
                        ),
                        20
                    )
                )

            except (TypeError, ValueError):

                raise ValueError(
                    "Invalid order item."
                )

            size = str(
                item.get("size", "M")
            )

            color = str(
                item.get("color", "")
            )

            product = con.execute(
                """
                SELECT *
                FROM products
                WHERE id=? AND active=1
                """,
                (pid,)
            ).fetchone()

            if not product:

                raise ValueError(
                    "A selected item is unavailable."
                )

            if qty > product["stock"]:

                raise ValueError(
                    "A selected item is out of stock."
                )

            sizes = [
                x.strip()
                for x in (
                    product["sizes"]
                    or "S,M,L,XL"
                ).split(",")
                if x.strip()
            ]

            colors = [
                x.strip()
                for x in (
                    product["colors"]
                    or ""
                ).split(",")
                if x.strip()
            ]

            if sizes and size not in sizes:

                raise ValueError(
                    "A selected size is invalid."
                )

            if colors and color not in colors:

                raise ValueError(
                    "A selected color is invalid."
                )

            unit_price = (
                product["sale_price"]
                if product["sale_price"] is not None
                else product["price"]
            )

            subtotal += unit_price * qty

            verified.append(
                (
                    product,
                    qty,
                    unit_price,
                    size,
                    color
                )
            )

        shipping = (
            0
            if subtotal >= 8000
            else 250
        )

        total = (
            subtotal
            + shipping
        )

        cur = con.execute(
            """
            INSERT INTO orders(
                user_id,
                customer_name,
                email,
                phone,
                address,
                city,
                province,
                postal_code,
                payment,
                subtotal,
                shipping,
                discount,
                total,
                status
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                user["id"]
                if user
                else None,

                str(
                    customer["name"]
                ).strip(),

                str(
                    customer["email"]
                ).strip(),

                str(
                    customer["phone"]
                ).strip(),

                str(
                    customer["address"]
                ).strip(),

                str(
                    customer["city"]
                ).strip(),

                str(
                    customer.get(
                        "province",
                        ""
                    )
                ).strip(),

                str(
                    customer.get(
                        "postal_code",
                        ""
                    )
                ).strip(),

                payment,

                subtotal,
                shipping,
                0,
                total,
                "Order Placed"
            )
        )

        order_id = cur.lastrowid

        for (
            product,
            qty,
            unit_price,
            size,
            color
        ) in verified:

            con.execute(
                """
                INSERT INTO order_items(
                    order_id,
                    product_id,
                    product_name,
                    quantity,
                    price,
                    size,
                    color
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    order_id,
                    product["id"],
                    product["name"],
                    qty,
                    unit_price,
                    size,
                    color
                )
            )

            con.execute(
                """
                UPDATE products
                SET stock=stock-?
                WHERE id=? AND stock>=?
                """,
                (
                    qty,
                    product["id"],
                    qty
                )
            )

        con.execute(
            """
            INSERT INTO order_events(
                order_id,
                status,
                note
            )
            VALUES(?,?,?)
            """,
            (
                order_id,
                "Order Placed",
                "Order received"
            )
        )

        if user:

            cid = cart_id_for(user)

            con.execute(
                """
                DELETE FROM cart_items
                WHERE cart_id=?
                """,
                (cid,)
            )

        con.commit()

        return jsonify({
            "ok": True,
            "order_id": order_id,
            "total": total,
            "status": "Order Placed"
        })

    except ValueError as e:

        con.rollback()

        return jsonify({
            "error": str(e)
        }), 400

    finally:

        con.close()


# ============================================================
# ACCOUNT ORDERS
# ============================================================

@app.get("/api/account/orders")
@login_required
def my_orders():

    con = get_db()

    orders = con.execute(
        """
        SELECT *
        FROM orders
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            current_user()["id"],
        )
    ).fetchall()

    result = []

    for order in orders:

        d = dict(order)

        d["items"] = [
            dict(item)
            for item in con.execute(
                """
                SELECT *
                FROM order_items
                WHERE order_id=?
                """,
                (order["id"],)
            ).fetchall()
        ]

        d["events"] = [
            dict(event)
            for event in con.execute(
                """
                SELECT *
                FROM order_events
                WHERE order_id=?
                ORDER BY id
                """,
                (order["id"],)
            ).fetchall()
        ]

        result.append(d)

    con.close()

    return jsonify(result)


# ============================================================
# ACCOUNT ADDRESSES
# ============================================================

@app.get("/api/account/addresses")
@login_required
def addresses():

    con = get_db()

    rows = [
        dict(row)
        for row in con.execute(
            """
            SELECT *
            FROM addresses
            WHERE user_id=?
            ORDER BY is_default DESC,id DESC
            """,
            (
                current_user()["id"],
            )
        ).fetchall()
    ]

    con.close()

    return jsonify(rows)


@app.post("/api/account/addresses")
@login_required
def address_add():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    required = [
        "full_name",
        "phone",
        "address",
        "city"
    ]

    if not all(
        str(data.get(key, "")).strip()
        for key in required
    ):

        return jsonify({
            "error": (
                "Complete all required "
                "address fields."
            )
        }), 400

    con = get_db()

    uid = current_user()["id"]

    default = (
        1
        if data.get("is_default")
        else 0
    )

    if default:

        con.execute(
            """
            UPDATE addresses
            SET is_default=0
            WHERE user_id=?
            """,
            (uid,)
        )

    con.execute(
        """
        INSERT INTO addresses(
            user_id,
            full_name,
            phone,
            address,
            city,
            province,
            postal_code,
            country,
            is_default
        )
        VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            uid,
            str(
                data.get(
                    "full_name",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "phone",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "address",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "city",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "province",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "postal_code",
                    ""
                )
            ).strip(),

            str(
                data.get(
                    "country",
                    "Pakistan"
                )
            ).strip(),

            default
        )
    )

    con.commit()
    con.close()

    return addresses()


@app.delete("/api/account/addresses/<int:aid>")
@login_required
def address_delete(aid):

    require_csrf()

    con = get_db()

    con.execute(
        """
        DELETE FROM addresses
        WHERE id=? AND user_id=?
        """,
        (
            aid,
            current_user()["id"]
        )
    )

    con.commit()
    con.close()

    return addresses()


# ============================================================
# ACCOUNT PROFILE
# ============================================================

@app.patch("/api/account/profile")
@login_required
def profile_update():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    name = str(
        data.get("name", "")
    ).strip()

    phone = str(
        data.get("phone", "")
    ).strip()

    if len(name) < 2:

        return jsonify({
            "error": "Name is required."
        }), 400

    con = get_db()

    con.execute(
        """
        UPDATE users
        SET name=?, phone=?
        WHERE id=?
        """,
        (
            name,
            phone,
            current_user()["id"]
        )
    )

    con.commit()
    con.close()

    return jsonify({
        "ok": True,
        "user": current_user()
    })


# ============================================================
# ADMIN - SUMMARY
# ============================================================

@app.get("/api/admin/summary")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_summary():

    con = get_db()

    data = {

        "sales": con.execute(
            """
            SELECT COALESCE(
                SUM(total),
                0
            )
            FROM orders
            WHERE status NOT IN(
                'Cancelled',
                'Refunded'
            )
            """
        ).fetchone()[0],

        "orders": con.execute(
            """
            SELECT COUNT(*)
            FROM orders
            """
        ).fetchone()[0],

        "customers": con.execute(
            """
            SELECT COUNT(*)
            FROM users
            WHERE role='customer'
            """
        ).fetchone()[0],

        "products": con.execute(
            """
            SELECT COUNT(*)
            FROM products
            """
        ).fetchone()[0],

        "low_stock": con.execute(
            """
            SELECT COUNT(*)
            FROM products
            WHERE stock<=5
            AND active=1
            """
        ).fetchone()[0],

        "pending": con.execute(
            """
            SELECT COUNT(*)
            FROM orders
            WHERE status IN(
                'Order Placed',
                'Confirmed',
                'Processing'
            )
            """
        ).fetchone()[0]
    }

    con.close()

    return jsonify(data)


# ============================================================
# ADMIN - PRODUCTS
# ============================================================

@app.get("/api/admin/products")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_products():

    con = get_db()

    rows = [
        public_product(row)
        for row in con.execute(
            """
            SELECT *
            FROM products
            ORDER BY id DESC
            """
        ).fetchall()
    ]

    con.close()

    return jsonify(rows)


@app.post("/api/admin/products")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_product_create():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    required = [
        "name",
        "category",
        "collection",
        "description",
        "price",
        "image"
    ]

    if not all(
        str(data.get(key, "")).strip()
        for key in required
    ):

        return jsonify({
            "error": (
                "Complete required "
                "product fields."
            )
        }), 400

    try:

        price = int(
            data["price"]
        )

        sale_price = (
            int(data["sale_price"])
            if str(
                data.get(
                    "sale_price",
                    ""
                )
            ).strip()
            else None
        )

        stock = int(
            data.get(
                "stock",
                0
            )
        )

    except (TypeError, ValueError):

        return jsonify({
            "error": (
                "Price, sale price and "
                "stock must be numbers."
            )
        }), 400

    con = get_db()

    cur = con.execute(
        """
        INSERT INTO products(
            name,
            category,
            collection,
            description,
            price,
            sale_price,
            image,
            badge,
            stock,
            featured,
            active,
            sku,
            colors,
            sizes,
            material,
            care,
            seo_title,
            seo_description
        )
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            str(data["name"]),
            str(data["category"]),
            str(data["collection"]),
            str(data["description"]),
            price,
            sale_price,
            str(data["image"]),
            str(data.get("badge", "")),
            stock,
            int(bool(
                data.get(
                    "featured",
                    1
                )
            )),
            int(bool(
                data.get(
                    "active",
                    1
                )
            )),
            str(data.get("sku", "")),
            str(data.get("colors", "")),
            str(
                data.get(
                    "sizes",
                    "S,M,L,XL"
                )
            ),
            str(data.get("material", "")),
            str(data.get("care", "")),
            str(data.get("seo_title", "")),
            str(
                data.get(
                    "seo_description",
                    ""
                )
            )
        )
    )

    product_id = cur.lastrowid

    con.commit()
    con.close()

    log_admin(
        current_user(),
        "Created product",
        "product",
        product_id
    )

    return jsonify({
        "ok": True,
        "id": product_id
    })


@app.put("/api/admin/products/<int:pid>")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_product_update(pid):

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    fields = [
        "name",
        "category",
        "collection",
        "description",
        "price",
        "sale_price",
        "image",
        "badge",
        "stock",
        "featured",
        "active",
        "sku",
        "colors",
        "sizes",
        "material",
        "care",
        "seo_title",
        "seo_description"
    ]

    sets = []
    values = []

    for field in fields:

        if field not in data:
            continue

        sets.append(
            f"{field}=?"
        )

        if (
            field == "sale_price"
            and str(
                data[field]
            ).strip() == ""
        ):

            values.append(None)

        elif field in {
            "price",
            "sale_price",
            "stock",
            "featured",
            "active"
        }:

            try:
                values.append(
                    int(data[field])
                )

            except (TypeError, ValueError):

                return jsonify({
                    "error": (
                        f"{field} must be "
                        "a number."
                    )
                }), 400

        else:

            values.append(
                data[field]
            )

    if not sets:

        return jsonify({
            "error": (
                "No changes supplied."
            )
        }), 400

    values.append(pid)

    con = get_db()

    cursor = con.execute(
        f"""
        UPDATE products
        SET {", ".join(sets)}
        WHERE id=?
        """,
        values
    )

    con.commit()
    con.close()

    if not cursor.rowcount:

        return jsonify({
            "error": "Product not found"
        }), 404

    log_admin(
        current_user(),
        "Updated product",
        "product",
        pid
    )

    return jsonify({
        "ok": True
    })


@app.delete("/api/admin/products/<int:pid>")
@role_required(
    "admin",
    "super_admin"
)
def admin_product_delete(pid):

    require_csrf()

    con = get_db()

    cursor = con.execute(
        """
        UPDATE products
        SET active=0
        WHERE id=?
        """,
        (pid,)
    )

    con.commit()
    con.close()

    if not cursor.rowcount:

        return jsonify({
            "error": "Product not found"
        }), 404

    log_admin(
        current_user(),
        "Archived product",
        "product",
        pid
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# ADMIN - ORDERS
# ============================================================

@app.get("/api/admin/orders")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_orders():

    con = get_db()

    rows = [
        dict(row)
        for row in con.execute(
            """
            SELECT *
            FROM orders
            ORDER BY id DESC
            """
        ).fetchall()
    ]

    con.close()

    return jsonify(rows)


@app.patch("/api/admin/orders/<int:oid>")
@role_required(
    "admin",
    "super_admin"
)
def admin_order_update(oid):

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status"
    )

    if status not in ORDER_STATUSES:

        return jsonify({
            "error": "Invalid status"
        }), 400

    con = get_db()

    order = con.execute(
        """
        SELECT id
        FROM orders
        WHERE id=?
        """,
        (oid,)
    ).fetchone()

    if not order:

        con.close()

        return jsonify({
            "error": "Order not found"
        }), 404

    con.execute(
        """
        UPDATE orders
        SET status=?
        WHERE id=?
        """,
        (
            status,
            oid
        )
    )

    con.execute(
        """
        INSERT INTO order_events(
            order_id,
            status,
            note
        )
        VALUES(?,?,?)
        """,
        (
            oid,
            status,
            "Updated by admin"
        )
    )

    con.commit()
    con.close()

    log_admin(
        current_user(),
        "Updated order status",
        "order",
        oid
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# ADMIN - CUSTOMERS
# ============================================================

@app.get("/api/admin/customers")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_customers():

    con = get_db()

    rows = [
        dict(row)
        for row in con.execute(
            """
            SELECT
                u.id,
                u.name,
                u.email,
                u.phone,
                u.role,
                u.active,
                u.created_at,
                COUNT(o.id) AS orders,
                COALESCE(
                    SUM(
                        CASE
                            WHEN o.status NOT IN(
                                'Cancelled',
                                'Refunded'
                            )
                            THEN o.total
                            ELSE 0
                        END
                    ),
                    0
                ) AS spent
            FROM users u
            LEFT JOIN orders o
                ON o.user_id=u.id
            WHERE u.role='customer'
            GROUP BY u.id
            ORDER BY u.id DESC
            """
        ).fetchall()
    ]

    con.close()

    return jsonify(rows)


@app.patch("/api/admin/customers/<int:uid>")
@role_required(
    "admin",
    "super_admin"
)
def admin_customer_update(uid):

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    active = int(
        bool(
            data.get(
                "active",
                1
            )
        )
    )

    con = get_db()

    cursor = con.execute(
        """
        UPDATE users
        SET active=?
        WHERE id=?
        AND role='customer'
        """,
        (
            active,
            uid
        )
    )

    con.commit()
    con.close()

    if not cursor.rowcount:

        return jsonify({
            "error": "Customer not found"
        }), 404

    log_admin(
        current_user(),
        "Updated customer",
        "customer",
        uid
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# ADMIN - SETTINGS
# ============================================================

@app.get("/api/admin/settings")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_settings():

    return jsonify(
        get_settings()
    )


@app.put("/api/admin/settings")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_settings_update():

    require_csrf()

    data = request.get_json(
        silent=True
    ) or {}

    con = get_db()

    for key, value in data.items():

        if str(key).startswith("_"):
            continue

        con.execute(
            """
            INSERT INTO site_settings(
                key,
                value
            )
            VALUES(?,?)
            ON CONFLICT(key)
            DO UPDATE SET
                value=excluded.value
            """,
            (
                str(key),
                str(value)
            )
        )

    con.commit()
    con.close()

    log_admin(
        current_user(),
        "Updated site settings",
        "settings"
    )

    return jsonify({
        "ok": True
    })


# ============================================================
# ADMIN - NEWSLETTER
# ============================================================

@app.get("/api/admin/newsletter")
@role_required(
    "admin",
    "editor",
    "super_admin"
)
def admin_newsletter():

    con = get_db()

    rows = [
        dict(row)
        for row in con.execute(
            """
            SELECT *
            FROM newsletter
            ORDER BY id DESC
            """
        ).fetchall()
    ]

    con.close()

    return jsonify(rows)


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "AJWEARS",
        "timestamp": now()
    })


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(403)
def forbidden(error):

    return jsonify({
        "error": "Forbidden"
    }), 403


@app.errorhandler(413)
def too_large(error):

    return jsonify({
        "error": "File too large"
    }), 413


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=(
            os.environ.get(
                "FLASK_DEBUG",
                "0"
            ) == "1"
        )
    )