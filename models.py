from datetime import datetime, timezone
from extensions import db

class Assessment(db.Model):
    __tablename__ = 'assessment'
    id                 = db.Column(db.Integer, primary_key=True)
    name               = db.Column(db.String(100), nullable=False)
    pdf_filename       = db.Column(db.String(255), nullable=True) 
    pdf_score_filename = db.Column(db.String(255), nullable=True)
    sharepoint_dir     = db.Column(db.String(255), nullable=True)
    applications = db.relationship(
        'Application',
        back_populates='assessment',
        cascade='all, delete-orphan'
    )
    criteria     = db.relationship(
        'Criteria',
        back_populates='assessment',
        cascade='all, delete-orphan'
    )
    assessors    = db.relationship(
        'Assessor',
        back_populates='assessment',
        cascade='all, delete-orphan'
    )

class Application(db.Model):
    __tablename__ = 'application'
    id                = db.Column(db.Integer, primary_key=True)
    code              = db.Column(db.String(50), nullable=False)
    assessment_id     = db.Column(
        db.Integer,
        db.ForeignKey('assessment.id', ondelete='CASCADE'),
        nullable=False
    )
    assessment        = db.relationship(
        'Assessment',
        back_populates='applications'
    )
    funding_requested = db.Column(db.Float, nullable=True)
    funding_given     = db.Column(db.Float, nullable=True)
    successful        = db.Column(db.Boolean, nullable=True, default=False)

class Criteria(db.Model):
    __tablename__ = 'criteria'
    id            = db.Column(db.Integer, primary_key=True)
    description   = db.Column(db.String(255), nullable=False)
    weight        = db.Column(db.Integer, nullable=False)
    assessment_id = db.Column(
        db.Integer,
        db.ForeignKey('assessment.id', ondelete='CASCADE'),
        nullable=False
    )
    assessment    = db.relationship(
        'Assessment',
        back_populates='criteria'
    )

class Assessor(db.Model):
    __tablename__ = 'assessor'
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    unique_token  = db.Column(db.String(32), nullable=False)
    access_code   = db.Column(db.String(8), nullable=False)
    assessment_id = db.Column(
        db.Integer,
        db.ForeignKey('assessment.id', ondelete='CASCADE'),
        nullable=False
    )
    assessment    = db.relationship(
        'Assessment',
        back_populates='assessors'
    )

class Score(db.Model):
    __tablename__ = 'score'
    id = db.Column(db.Integer, primary_key=True)
    assessor_id = db.Column(db.Integer, db.ForeignKey('assessor.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('application.id'), nullable=False)
    criteria_id = db.Column(db.Integer, db.ForeignKey('criteria.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    finalised = db.Column(db.Boolean, default=False, nullable=False)
