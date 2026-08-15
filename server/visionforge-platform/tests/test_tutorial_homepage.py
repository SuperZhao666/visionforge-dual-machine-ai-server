import os
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tutorial-homepage")

from fastapi.testclient import TestClient

from app.main import app


class TutorialHomepageTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_homepage_is_the_dual_machine_tutorial(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("VisionForge 双机推流使用教程", response.text)
        self.assertIn("先连通画面", response.text)
        self.assertIn("CAT6 千兆有线", response.text)
        self.assertIn("UDP 局域网无线", response.text)
        self.assertIn("MAKCU 有线盒子", response.text)
        self.assertIn("蓝牙 HID 无线", response.text)
        self.assertIn("host-events.jsonl", response.text)
        self.assertIn("host-metrics-v6.csv", response.text)
        self.assertIn("问题描述模板", response.text)
        self.assertNotIn("COMING SOON", response.text)
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    def test_homepage_exposes_working_admin_login_entry(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('class="tutorial-admin-link"', response.text)
        self.assertIn('href="/login"', response.text)
        self.assertIn("管理员登录", response.text)

        login = self.client.get("/login")
        self.assertEqual(login.status_code, 200, login.text)
        self.assertIn('action="/auth/login"', login.text)

    def test_tutorial_assets_are_publicly_served(self):
        paths = (
            "/static/css/tutorial.css?v=3",
            "/static/img/tutorial/host-home.png",
            "/static/img/tutorial/mobile-home.png",
            "/static/img/tutorial/mobile-control.png",
            "/static/img/tutorial/mobile-log-export-guide.png",
        )

        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, path)
                self.assertGreater(len(response.content), 1_000, path)


if __name__ == "__main__":
    unittest.main()
