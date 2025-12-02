from app import create_app, db
from app.models import User

app = create_app()
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False

with app.app_context():
    # Ensure admin exists
    admin = User.query.filter_by(email="admin@tenshiguard.ai").first()
    if not admin:
        print("Admin user not found!")
        exit(1)

    with app.test_client() as client:
        # Login
        login_resp = client.post("/login", data={
            "email": "admin@tenshiguard.ai",
            "password": "Admin123!"
        }, follow_redirects=True)
        
        if b"Welcome back" not in login_resp.data and b"Dashboard" not in login_resp.data:
            print("Login failed!")
            print(login_resp.data.decode())
            exit(1)
            
        print("Login successful.")
        
        # Access Setup Agent Page
        try:
            resp = client.get("/dashboard/setup-agent")
            print(f"Status Code: {resp.status_code}")
            if resp.status_code == 500:
                print("500 Error Encountered!")
                # In test mode, Flask might propagate the exception
            else:
                print("Page loaded successfully.")
                print(resp.data.decode()[:500]) # Print first 500 chars
        except Exception as e:
            print(f"Exception caught: {e}")
            import traceback
            traceback.print_exc()
