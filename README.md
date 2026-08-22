# PartnerHub — Real Full-Stack MVP

A runnable business-partner marketplace MVP.

## Included
- User registration/login with secure password hashing
- Profiles: city, skills, investment capacity, interests
- Business opportunity listings
- Partner/business search
- Compatibility score
- Interested / match workflow
- Real chat persistence
- Notifications
- Report/block endpoints
- Admin dashboard API
- SQLite database (easy to move to PostgreSQL)
- Responsive web UI
- Docker support

## Run
Python 3.11+:
```bash
pip install -r requirements.txt
uvicorn app:app --reload
```
Open http://127.0.0.1:8000

Demo admin:
email: admin@partnerhub.local
password: ChangeMe123!

IMPORTANT FOR PRODUCTION:
- Change SECRET_KEY and admin password.
- Use PostgreSQL.
- Put the app behind HTTPS.
- Add a real SMS/OTP provider.
- Add a production payment gateway.
- Add KYC/identity verification only through a compliant provider.
- Configure email/push notifications.
- Have legal counsel review partnership agreements, privacy policy and terms.
