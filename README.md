# AJWEARS Full-Stack Ecommerce

AJWEARS is a Flask + SQLite luxury fashion ecommerce starter upgraded with:

- responsive luxury storefront
- customer registration/login
- persistent database-backed cart and wishlist
- customer account dashboard
- order history and addresses
- role-based admin dashboard
- product CRUD/archive and inventory fields
- order status management
- customer management
- editable site settings
- newsletter storage
- server-side pricing/stock validation
- CSRF protection for state-changing API calls
- secure password hashing
- mobile/tablet/desktop responsive layouts

## Run locally

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`.

## Admin setup

For safety, the app does not ship with a hard-coded production admin password. Create an admin from the SQLite database or add an initial setup mechanism appropriate to your deployment. The role values are `customer`, `editor`, `admin`, `super_admin`.

Example one-time Python command:

```python
from werkzeug.security import generate_password_hash
# INSERT a user row with password_hash=generate_password_hash('your-password') and role='super_admin'
```

For production, set a strong `SECRET_KEY` environment variable and keep debug disabled.

## Important production integrations

Payment gateways, transactional email, SMS, cloud image storage, and real shipping integrations require provider credentials and should be configured through environment variables. The current checkout supports Cash on Delivery and Bank Transfer without pretending that a payment gateway has processed a card payment.
