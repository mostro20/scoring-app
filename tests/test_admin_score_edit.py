import os
import unittest


os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['CAPTCHA_SECRET'] = 'test-captcha-secret-with-at-least-32-bytes'
os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

from app import app  # noqa: E402
from extensions import db  # noqa: E402
from models import (  # noqa: E402
    Application,
    Assessment,
    Assessor,
    Criteria,
    Score,
    ScoreHistory,
)


class AdminScoreEditTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

        with app.app_context():
            db.drop_all()
            db.create_all()

            assessment = Assessment(name='Admin score edit test')
            db.session.add(assessment)
            db.session.flush()

            assessor = Assessor(
                name='Test assessor',
                unique_token='admin-score-edit-token',
                access_code='testcode',
                assessment_id=assessment.id,
            )
            application = Application(code='A', assessment_id=assessment.id)
            criterion = Criteria(
                description='Criterion',
                weight=100,
                assessment_id=assessment.id,
            )
            db.session.add_all([assessor, application, criterion])
            db.session.flush()

            score = Score(
                assessor_id=assessor.id,
                application_id=application.id,
                criteria_id=criterion.id,
                score=4,
                comment='Original comment',
                finalised=True,
            )
            db.session.add(score)
            db.session.commit()

            self.assessment_id = assessment.id
            self.score_id = score.id

        with self.client.session_transaction() as session_data:
            session_data['admin_authed'] = True

    def test_score_controls_are_associated_with_valid_row_form(self):
        response = self.client.get(
            f'/admin/scores?assessment_id={self.assessment_id}'
        )

        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        form_id = f'edit-score-{self.score_id}'
        self.assertIn(f'<form id="{form_id}"', page)
        self.assertIn(f'name="score" min="0" max="10" step="1" class="admin-input" value="4" form="{form_id}"', page)
        self.assertIn(f'name="comment" class="admin-input" value="Original comment" title="Original comment" form="{form_id}"', page)

    def test_edit_score_saves_value_and_history(self):
        response = self.client.post(
            f'/admin/edit-score/{self.score_id}',
            data={'score': '8', 'comment': 'Updated comment'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.location.endswith(
                f'/admin/scores?assessment_id={self.assessment_id}'
                f'#auditScores-{self.score_id}'
            )
        )

        with app.app_context():
            score = db.session.get(Score, self.score_id)
            history = ScoreHistory.query.filter_by(score_id=self.score_id).one()

            self.assertEqual(score.score, 8)
            self.assertEqual(score.comment, 'Updated comment')
            self.assertEqual(history.previous_score, 4)
            self.assertEqual(history.previous_comment, 'Original comment')
            self.assertTrue(history.previous_finalised)
            self.assertEqual(history.action, 'admin_edit')
            self.assertEqual(history.version, 1)


if __name__ == '__main__':
    unittest.main()
