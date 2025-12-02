import unittest
import os
import sys
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db, bcrypt
from app.models.user import User
from app.models.organization import Organization
from config import Config

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

class PreFlightCheck(unittest.TestCase):
    def setUp(self):
        os.environ["TESTING"] = "true"
        self.app = create_app()
        self.app.config.from_object(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create Test Data
        self.org = Organization(name="Test Org", sector="academic", agent_token="test-token-123")
        db.session.add(self.org)
        db.session.commit()

        self.admin_user = User(
            username="admin",
            email="admin@test.com",
            role="admin",
            organization_id=self.org.id,
            is_enabled=True
        )
        self.admin_user.set_password("password")
        db.session.add(self.admin_user)

        self.normal_user = User(
            username="user",
            email="user@test.com",
            role="user",
            organization_id=self.org.id,
            is_enabled=True
        )
        self.normal_user.set_password("password")
        db.session.add(self.normal_user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, email, password):
        return self.client.post('/login', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)

    def test_01_health_check(self):
        """Verify the app is running and health endpoint works."""
        response = self.client.get('/healthz')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['ok'], True)
        print("[OK] Health Check Passed")

    def test_02_auth_flow(self):
        """Verify login and logout."""
        # Login
        response = self.login("admin@test.com", "password")
        self.assertIn(b"Welcome back", response.data)
        
        # Logout
        response = self.client.get('/logout', follow_redirects=True)
        if b"You have been logged out" not in response.data:
            print(f"DEBUG: Auth Flow Failed. Response: {response.data[:500]}")
        self.assertIn(b"You have been logged out", response.data)
        print("[OK] Auth Flow Passed")

    def test_03_dashboard_access(self):
        """Verify dashboard pages load for logged-in user."""
        self.login("admin@test.com", "password")
        
        pages = [
            '/dashboard/user', # User dashboard
            '/dashboard/devices',
            '/dashboard/live-events',
            '/dashboard/ai',
            '/dashboard/profile',
            '/subscription'
        ]
        
        for page in pages:
            response = self.client.get(page)
            self.assertEqual(response.status_code, 200, f"Failed to load {page}")
        print("[OK] Dashboard Access Passed")

    def test_04_admin_permissions(self):
        """Verify admin-only pages."""
        # Admin should access
        self.login("admin@test.com", "password")
        response = self.client.get('/manage-users')
        self.assertEqual(response.status_code, 200)

        # User should be denied or redirected (depending on implementation)
        # In our case, role_required usually flashes a message and redirects
        self.client.get('/logout')
        self.login("user@test.com", "password")
        response = self.client.get('/manage-users', follow_redirects=True)
        # Check for unauthorized flash message or redirect to dashboard (look for "Overview" or "TenshiGuard")
        if not (b"Unauthorized" in response.data or b"Overview" in response.data or b"TenshiGuard" in response.data):
             print(f"DEBUG: Admin Perms Failed. Response: {response.data[:500]}")
        self.assertTrue(b"Unauthorized" in response.data or b"Overview" in response.data or b"TenshiGuard" in response.data)
        print("[OK] Admin Permissions Passed")

    def test_05_api_endpoints(self):
        """Verify API endpoints return valid JSON."""
        self.login("admin@test.com", "password")
        
        # SOS Latest
        response = self.client.get('/api/sos/latest')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        
        # AI Latest (requires API key usually, but let's check if it's protected or accessible via session)
        # The route uses @require_api_key which checks headers. 
        # Let's mock the header.
        headers = {'X-Dashboard-Key': Config.DASHBOARD_API_KEY}
        response = self.client.get('/api/dashboard/ai/latest', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.is_json)
        print("[OK] API Endpoints Passed")

if __name__ == '__main__':
    unittest.main(verbosity=2)
