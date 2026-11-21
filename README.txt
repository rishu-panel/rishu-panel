AYUSH PANEL

Files:
- app.py
- templates/index.html
- MaJorLogin.py
- FriEndRequEst.py
- ALLinOne.PY
- BiOCheck.py
- PROFILE-ITEM-ADDER.py

Setup:
1. Keep all Python files in this same folder.
2. Python 3.10+ recommended.
3. Install dependencies: pip install -r requirements.txt
4. Run locally: python app.py
5. Open http://127.0.0.1:5000

Security:
- The hosted panel is reachable by anyone with its URL; it has no separate panel passcode.
- Use only game accounts you own or are authorized to manage.
- UID/password or access-token login is sent to the backend to generate a JWT.
- JWTs are held in process memory for the browser session and cleared on logout or server restart.
- Use Gunicorn and HTTPS for public hosting; do not expose Flask's development server.

Profile Item Adder sets profile gallery/showcase IDs; it does not grant inventory ownership.
The included game endpoints/protocols are reverse-engineered and may stop working when the game updates.
