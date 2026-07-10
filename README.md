# DayCatch Backend (FastAPI)

Auth flow:

1. **Frontend** signs the user in with **Firebase Phone Auth** (OTP delivery + verification + reCAPTCHA all handled by Firebase).
2. **Backend** receives the resulting **Firebase ID token**, verifies it with the Admin SDK, looks the phone up in our `users` table to confirm role membership, and issues a **DayCatch session JWT** for subsequent API calls.

So Firebase = identity. Backend = roles + permissions + session.

## Setup

```bash
# from the backend/ folder
python -m venv venv

# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env       # edit JWT_SECRET and seed phones
```

### Firebase Admin credentials

Firebase Console → ⚙️ Project Settings → **Service accounts** → **Generate new private key**. Save the downloaded JSON as `backend/firebase-service-account.json` (gitignored). Point `FIREBASE_SERVICE_ACCOUNT_PATH` at it in `.env`.

If you're deploying on GCP and want Application Default Credentials, leave `FIREBASE_SERVICE_ACCOUNT_PATH` blank and ensure `GOOGLE_APPLICATION_CREDENTIALS` or workload identity is set.

### Enable Phone sign-in

Firebase Console → **Authentication** → **Sign-in method** → **Phone** → Enable. Add your dev hostnames under **Settings → Authorized domains**.

### Migrate (run on demand, not on startup)

The app no longer creates tables on boot. Run the migration once (and again
after model changes or when you add seed phones to `.env`):

```bash
python migrate.py            # create schema + tables, then seed users
python migrate.py --no-seed  # schema + tables only
```

### Run

```bash
uvicorn app:app --reload --port 8000
```

Swagger: http://localhost:8000/docs

## Endpoints

| Method | Path             | Body                | Description                                     |
| ------ | ---------------- | ------------------- | ----------------------------------------------- |
| POST   | `/auth/session`  | `{id_token, role}`  | Verifies Firebase ID token → returns session JWT |
| GET    | `/auth/me`       | (Bearer)            | Returns current user                            |
| GET    | `/health`        |                     | Liveness                                        |

`role` is one of `admin`, `distributor`, `kiosk`.

## Users

There's no public sign-up — only the Central Admin onboards distributors and
kiosk owners. Users live in the `daycatch.users` table and are managed in the
database directly (or via admin onboarding endpoints, TBD) — **not** seeded
from `.env`. Each row has `phone`, `role`, `name`, `is_active`.

To add a user manually:

```sql
INSERT INTO daycatch.users (phone, role, name, is_active, created_at)
VALUES ('+919876543210', 'distributor', 'Ravi', true, now());
```

## Notes

- The session JWT is HS256 with `JWT_SECRET`. Use a long random string.
- The Firebase ID token itself is not stored — we just verify it once at sign-in.
- Switch to Postgres by setting `DATABASE_URL=postgresql+psycopg://...`.
