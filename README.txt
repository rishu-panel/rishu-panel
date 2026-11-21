RISHU CONTROL PANEL

Files:
- app.py
- templates/index.html
- MaJorLogin.py
- FriEndRequEst.py
- ALLinOne.PY
- BiO✓.py
- PROFILE-ITEM-ADDER.py

Setup:
1. Keep all Python files in this same folder.
2. Python 3.10+ recommended.
3. Install dependencies: pip install -r requirements.txt
4. Run: python app.py
5. Open http://127.0.0.1:5000

Security:
- The app binds to localhost only.
- Do not expose this development server publicly.
- Do not share passwords, access tokens, or JWTs.
- JWTs are held in process memory and cleared on logout/server restart.
- Use only accounts you own or are authorized to manage.

Profile Item Adder sets profile gallery/showcase IDs; it does not grant inventory ownership.
The included game endpoints/protocols are reverse-engineered and may stop working when the game updates.
