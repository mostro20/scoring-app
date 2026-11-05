import os
import time
import unittest
from datetime import timedelta


os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['CAPTCHA_SECRET'] = 'test-captcha-secret-with-at-least-32-bytes'
os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

from app import app  # noqa: E402
from extensions import db  # noqa: E402
from models import Application, Assessment, Assessor, Criteria  # noqa: E402


class AssessorSessionTests(unittest.TestCase):
    def setUp(self):
        app.config.update(
            TESTING=True,
            PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
        )
        self.client = app.test_client()

        with app.app_context():
            db.drop_all()
            db.create_all()

            assessment = Assessment(name='Session test')
            db.session.add(assessment)
            db.session.flush()

            assessor = Assessor(
                name='Test assessor',
                unique_token='session-test-token',
                access_code='testcode',
                assessment_id=assessment.id,
            )
            db.session.add_all([
                assessor,
                Application(code='A', assessment_id=assessment.id),
                Criteria(description='Criterion', weight=100, assessment_id=assessment.id),
            ])
            db.session.commit()
            self.assessor_id = assessor.id

    def set_session_age(self, age_seconds):
        with self.client.session_transaction() as session_data:
            session_data.permanent = True
            session_data['assessor_id'] = self.assessor_id
            session_data['assessor_logged_in_at'] = time.time() - age_seconds

    def test_login_creates_timed_permanent_session(self):
        response = self.client.post(
            '/score/session-test-token/login',
            data={'access_code': 'testcode'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/score/session-test-token'))
        with self.client.session_transaction() as session_data:
            self.assertTrue(session_data.permanent)
            self.assertEqual(session_data['assessor_id'], self.assessor_id)
            self.assertIn('assessor_logged_in_at', session_data)

        score_page = self.client.get('/score/session-test-token')
        self.assertEqual(score_page.status_code, 200)
        self.assertNotIn(b'session-timer', score_page.data)
        self.assertIn(b'window.location.replace(assessorLoginUrl)', score_page.data)

    def test_expired_page_session_redirects_to_login(self):
        self.set_session_age(timedelta(hours=24, seconds=1).total_seconds())

        response = self.client.get('/score/session-test-token')

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.location.endswith('/score/session-test-token/login?expired=1')
        )

        login_page = self.client.get(response.location)
        self.assertIn(b'Your session expired', login_page.data)

    def test_expired_autosave_returns_login_url(self):
        self.set_session_age(timedelta(hours=24, seconds=1).total_seconds())

        response = self.client.post(
            '/score/session-test-token/autosave',
            json={
                'application_id': 1,
                'criteria_id': 1,
                'score': '8',
                'comment': 'Test comment',
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json['error'], 'not-authorized')
        self.assertTrue(response.json['login_url'].endswith('/login?expired=1'))

    def test_captcha_and_pdf_generation_with_upgraded_dependencies(self):
        admin_login = self.client.get('/admin/login')
        self.assertEqual(admin_login.status_code, 200)
        self.assertIn(b'captcha-hash', admin_login.data)

        self.client.post(
            '/score/session-test-token/login',
            data={'access_code': 'testcode'},
        )
        report = self.client.post(
            '/score/session-test-token/report.pdf',
            data={
                'score-1-1': '8',
                'comment-1-1': 'Dependency upgrade smoke test',
            },
        )

        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, 'application/pdf')
        self.assertTrue(report.data.startswith(b'%PDF'))


if __name__ == '__main__':
    unittest.main()
