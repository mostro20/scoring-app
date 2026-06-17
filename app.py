# app.py
import os, secrets, time, requests, json, re, logging
from io import BytesIO
from flask import Flask, session, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, send_file
from fpdf import FPDF
from extensions import db
from flask_migrate import Migrate
from pathlib import Path
from functools import wraps
import models
import time
import re
from services.scores import build_scores_summary_context
from collections import defaultdict
from itsdangerous import URLSafeSerializer
from datetime import timedelta
from flask_simple_captcha import CAPTCHA
from werkzeug.utils import secure_filename
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=False)

class _FpdfSvgWarningFilter(logging.Filter):
    def filter(self, record):
        return not record.getMessage().startswith('Ignoring unsupported SVG tag:')

logging.getLogger('fpdf').addFilter(_FpdfSvgWarningFilter())
logging.getLogger('fpdf.svg').addFilter(_FpdfSvgWarningFilter())

def _clean_provider_name(code: str) -> str:
    """Strip leading digits + '.' or ':' + space, then anything from '('."""
    s = re.sub(r'^\s*\d+[:\.]\s*', '', code or '')
    s = re.sub(r'\s*\(.*$', '', s)
    return s.strip()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['ADMIN_KEYPHRASE'] = os.getenv('ADMIN_KEYPHRASE')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    serializer = URLSafeSerializer(app.config['SECRET_KEY'])
    
    #app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scoring.db'
    default_db_path = os.path.join(app.instance_path, "scoring.db")  # absolute path
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{default_db_path}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    #app.config['UPLOAD_FOLDER'] = 'uploads'
    default_upload_dir = Path(app.instance_path) / "uploads"
    upload_dir = os.getenv("UPLOAD_FOLDER", str(default_upload_dir))
    Path(upload_dir).mkdir(parents=True, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_dir
    
    SIMPLE_CAPTCHA = CAPTCHA(config={
        # keep this stable in env, e.g. CAPTCHA_SECRET="a-long-random-string"
        'SECRET_CAPTCHA_KEY': os.environ.get('CAPTCHA_SECRET') or secrets.token_urlsafe(48),
        'CAPTCHA_LENGTH': 7,
        'CAPTCHA_DIGITS': True,
        'EXPIRE_SECONDS': 3600,
        'CAPTCHA_IMG_FORMAT': 'JPEG'
    })
    SIMPLE_CAPTCHA.init_app(app)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    API_URL       = os.getenv('api_url_var')
    CLIENT_ID     = os.getenv('client_id_var')
    CLIENT_SECRET = os.getenv('client_secret_var')

    TOKEN_INFO = {"access_token": None, "expires_at": 0}
    GRAPHQL_URL = os.getenv('graph_api_url')
    
    # Initialize the shared SQLAlchemy instance with this app
    db.init_app(app)

    migrate = Migrate(app, db, render_as_batch=True)
    
    # Import models after db.init_app to ensure they are registered
    from models import Application, Criteria, Assessor, Score, Assessment, ScoreHistory

    def get_token():
        """Fetch a new token if expired or missing."""
        if not TOKEN_INFO["access_token"] or time.time() >= TOKEN_INFO["expires_at"]:
            print("Fetching new token...")
            response = requests.post(
                API_URL,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "client_credentials"
                }
            )
            if response.status_code == 200:
                data = response.json()
                TOKEN_INFO["access_token"] = data["access_token"]
                TOKEN_INFO["expires_at"] = time.time() + data["expires_in"]
            else:
                return {"error": "Failed to fetch token", "details": response.text}, 500
        return TOKEN_INFO["access_token"]

    def admin_login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get('admin_authed'):
                # send them to the login route which creates the captcha
                return redirect(url_for('admin_login', next=request.url))
            return f(*args, **kwargs)
        return wrapper

    def safe_download_filename(value):
        cleaned = re.sub(r'[\\/\r\n\t]+', '-', value or '')
        cleaned = re.sub(r'\s+', ' ', cleaned).strip(' .')
        return cleaned or 'Individual Panel Scores.pdf'

    def pdf_text(value):
        text = '' if value is None else str(value)
        text = text.replace('\r\n', '\n').replace('\r', '\n').replace('\t', ' ')
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', text)

    class IndividualScoresPDF(FPDF):
        def __init__(self, assessor_name, assessment_name, logo_path):
            super().__init__(orientation='P', unit='mm', format='A4')
            self.assessor_name = pdf_text(assessor_name)
            self.assessment_name = pdf_text(assessment_name)
            self.logo_path = logo_path
            self.set_auto_page_break(auto=True, margin=18)
            font_dir = Path(app.root_path) / 'report_processing'
            self.add_font('DejaVu', '', str(font_dir / 'DejaVuSans.ttf'))
            self.add_font('DejaVu', 'B', str(font_dir / 'DejaVuSans-Bold.ttf'))
            self.add_font('DejaVuCondensed', '', str(font_dir / 'DejaVuSansCondensed.ttf'))

        def header(self):
            self.set_fill_color(255, 255, 255)
            self.rect(0, 0, self.w, self.h, style='F')
            if self.logo_path.exists():
                self.image(str(self.logo_path), x=14, y=11, w=34)
            self.set_xy(54, 13)
            self.set_font('DejaVu', 'B', 10)
            self.set_text_color(16, 34, 38)
            self.multi_cell(
                142,
                5,
                f"{self.assessor_name} | {self.assessment_name}",
                border=0,
                align='R',
                new_x='LMARGIN',
                new_y='NEXT'
            )
            self.set_draw_color(0, 132, 128)
            self.line(14, 29, 196, 29)
            self.set_xy(14, 36)

        def footer(self):
            pass

    def score_value_from_request(form, score_dict, app_id, criteria_id):
        key = f"{app_id}-{criteria_id}"
        form_key = f"score-{app_id}-{criteria_id}"
        posted_value = form.get(form_key)
        if posted_value not in (None, ''):
            try:
                score_int = int(posted_value)
                if 0 <= score_int <= 10:
                    return score_int
            except ValueError:
                pass
        return score_dict[key].score if key in score_dict else None

    def comment_value_from_request(form, score_dict, app_id, criteria_id):
        key = f"{app_id}-{criteria_id}"
        form_key = f"comment-{app_id}-{criteria_id}"
        if form_key in form:
            return form.get(form_key) or ''
        return score_dict[key].comment if key in score_dict and score_dict[key].comment else ''

    def add_wrapped_label_value(pdf, label, value, label_width=24):
        y = pdf.get_y()
        pdf.set_font('DejaVu', 'B', 9)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(label_width, 5, label)
        pdf.set_xy(pdf.l_margin + label_width, y)
        pdf.set_font('DejaVu', '', 9)
        pdf.set_text_color(71, 85, 105)
        pdf.multi_cell(0, 5, pdf_text(value or 'None provided'), new_x='LMARGIN', new_y='NEXT')

    def build_individual_scores_pdf(assessor, assessment, applications, criteria, score_dict, form=None):
        form = form or {}
        pdf = IndividualScoresPDF(
            assessor_name=assessor.name,
            assessment_name=assessment.name,
            logo_path=Path(app.static_folder) / 'HNC-logo-lockup-color.svg'
        )
        pdf.set_title(pdf_text(f"Individual Panel Scores - {assessor.name} - {assessment.name}"))
        pdf.set_author('HNC Scoring App')
        pdf.add_page()

        pdf.set_font('DejaVu', 'B', 18)
        pdf.set_text_color(16, 34, 38)
        pdf.multi_cell(0, 8, 'Individual Panel Scores', new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('DejaVu', '', 10)
        pdf.set_text_color(71, 85, 105)
        pdf.multi_cell(0, 6, pdf_text(f"Assessor: {assessor.name}"), new_x='LMARGIN', new_y='NEXT')
        pdf.multi_cell(0, 6, pdf_text(f"Assessment: {assessment.name}"), new_x='LMARGIN', new_y='NEXT')
        pdf.ln(5)

        for index, app_entry in enumerate(applications):
            if index:
                pdf.ln(3)

            estimated_block_height = 18 + (len(criteria) * 28)
            if pdf.get_y() + min(estimated_block_height, 78) > pdf.page_break_trigger:
                pdf.add_page()

            pdf.set_fill_color(238, 249, 248)
            pdf.set_draw_color(173, 223, 218)
            pdf.set_text_color(12, 84, 86)
            pdf.set_font('DejaVu', 'B', 14)
            pdf.cell(0, 10, pdf_text(f"Applicant {app_entry.code}"), border=1, ln=1, fill=True)

            total = 0
            has_score = False
            for crit in criteria:
                score_value = score_value_from_request(form, score_dict, app_entry.id, crit.id)
                if score_value is not None:
                    total += score_value * (crit.weight / 10)
                    has_score = True

            pdf.set_font('DejaVu', '', 9)
            pdf.set_text_color(71, 85, 105)
            weighted_text = f"Weighted score: {total:.2f} / 100" if has_score else "Weighted score: Not scored"
            pdf.cell(0, 7, weighted_text, ln=1)
            pdf.ln(1)

            for crit in criteria:
                if pdf.get_y() + 34 > pdf.page_break_trigger:
                    pdf.add_page()

                score_value = score_value_from_request(form, score_dict, app_entry.id, crit.id)
                comment_value = comment_value_from_request(form, score_dict, app_entry.id, crit.id)
                score_text = f"{score_value} / 10" if score_value is not None else "Not scored"

                pdf.set_fill_color(248, 250, 252)
                pdf.set_draw_color(226, 232, 240)
                start_y = pdf.get_y()
                pdf.rect(pdf.l_margin, start_y, pdf.epw, 8, style='FD')
                pdf.set_xy(pdf.l_margin + 3, start_y + 1.5)
                pdf.set_font('DejaVu', 'B', 10)
                pdf.set_text_color(15, 23, 42)
                pdf.multi_cell(pdf.epw - 6, 5, pdf_text(f"{crit.description} ({crit.weight}%)"), new_x='LMARGIN', new_y='NEXT')
                pdf.ln(1)

                add_wrapped_label_value(pdf, 'Score:', score_text)
                add_wrapped_label_value(pdf, 'Comments:', comment_value or 'No comments provided')
                pdf.ln(3)

        output = pdf.output(dest='S')
        if isinstance(output, str):
            output = output.encode('latin-1')
        return BytesIO(bytes(output))

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            c_hash = request.form.get('captcha-hash')
            c_text = request.form.get('captcha-text')
            if not SIMPLE_CAPTCHA.verify(c_text, c_hash):
                flash("CAPTCHA failed. Please try again.")
                return render_template('admin_login.html', captcha=SIMPLE_CAPTCHA.create())
            keyphrase = request.form.get('keyphrase', '')
            if keyphrase == os.environ.get('ADMIN_KEYPHRASE'):
                session['admin_authed'] = True
                dest = request.args.get('next') or url_for('admin')  # or wherever your admin home is
                return redirect(dest)
            else:
                flash("Invalid keyphrase.")
                return render_template('admin_login.html', captcha=SIMPLE_CAPTCHA.create())

        # GET
        return render_template('admin_login.html', captcha=SIMPLE_CAPTCHA.create())

    @app.route('/')
    def index():
        return render_template('index.html')


    @app.route('/admin', methods=['GET', 'POST'])
    @admin_login_required
    def admin():
        from werkzeug.utils import secure_filename  # Ensure this is imported
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected = None
        apps_txt = criteria_txt = assessors_txt = sharepoint_dir = map_url = ''

        if request.method == 'GET':
            aid = request.args.get('assessment_id')
            if aid:
                selected = Assessment.query.get(aid)
                # build newline-delimited strings for textareas
                apps_txt = '\n'.join(a.code for a in selected.applications)
                criteria_txt = '\n'.join(f"{c.description}|{c.weight}" for c in selected.criteria)
                assessors_txt = '\n'.join(m.name for m in selected.assessors)
                sharepoint_dir = selected.sharepoint_dir
                map_url = selected.map_url

        if request.method == 'POST':
            aid = request.form.get('assessment_id')
            name = request.form['assessment_name']
            apps_raw      = request.form.get('applications','').strip().splitlines()
            
            criteria_raw  = request.form.get('criteria','').strip().splitlines()
            assessors_raw = request.form.get('assessors','').strip().splitlines()
            sharepoint_dir= request.form['sharepoint_dir']
            map_url = (request.form.get("map_url") or "").strip()

            # load or create the Assessment
            if aid:
                selected = Assessment.query.get(aid)
                selected.name = name
                selected.sharepoint_dir = sharepoint_dir
                selected.map_url = map_url
            else:
                selected = Assessment(
                    name=name, 
                    sharepoint_dir=sharepoint_dir,
                    map_url=map_url
                )
                db.session.add(selected)
                db.session.flush()  # so selected.id is available

            # ----- Applications -----
            # remove old apps, add new
            selected.applications[:] = []
            for code in apps_raw:
                code = code.strip()
                if code:
                    selected.applications.append(
                        Application(code=code, assessment_id=selected.id)
                    )

            # ----- Criteria -----
            selected.criteria[:] = []
            for line in criteria_raw:
                parts = line.split('|', 1)
                if len(parts) == 2:
                    desc = parts[0].strip()
                    try:
                        wt = int(parts[1].strip())
                    except ValueError:
                        continue
                    selected.criteria.append(
                        Criteria(description=desc, weight=wt, assessment_id=selected.id)
                    )

            # ----- Assessors -----
            selected.assessors[:] = []
            for name in assessors_raw:
                nm = name.strip()
                if not nm:
                    continue
                token      = secrets.token_urlsafe(16)
                access_code= secrets.token_hex(4)
                selected.assessors.append(
                    Assessor(
                    name=nm,
                    unique_token=token,
                    access_code=access_code,
                    assessment_id=selected.id
                    )
                )

            # ----- PDF uploads -----
            for field, attr in (('pdf_file', 'pdf_filename'),
                                ('pdf_file_score', 'pdf_score_filename')):
                f = request.files.get(field)
                if f and f.filename:
                    filename = secure_filename(f.filename)
                    dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    f.save(dest)
                    setattr(selected, attr, filename)
            
            db.session.commit()
            flash(aid and "Assessment updated successfully." or "New assessment created.")
            return redirect(url_for('admin', assessment_id=selected.id))

        return render_template(
            'admin.html',
            assessments=assessments,
            selected_assessment=selected,
            applications_text=apps_txt,
            criteria_text=criteria_txt,
            assessors_text=assessors_txt,
            sharepoint_dir=sharepoint_dir,
            map_url=map_url,
        )

    @app.route('/admin/scores', methods=['GET', 'POST'])
    @admin_login_required
    def admin_scores():
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected_assessment = None
        raw_scores = []
        
        if request.method == 'POST' and request.form.get('publish'):
                aid = request.form.get('assessment_id')
                if aid:
                    # Save each application’s new values
                    for key, value in request.form.items():
                        # funding_requested-<app_id>, funding_given-<app_id>, successful-<app_id>
                        if key.startswith('funding_requested-'):
                            app_id = int(key.split('-',1)[1])
                            app = Application.query.get(app_id)
                            app.funding_requested = float(value) if value else None
                        elif key.startswith('funding_given-'):
                            app_id = int(key.split('-',1)[1])
                            app = Application.query.get(app_id)
                            app.funding_given = float(value) if value else None
                        elif key.startswith('successful-'):
                            app_id = int(key.split('-',1)[1])
                            app = Application.query.get(app_id)
                            app.successful = True
                    db.session.commit()
                    flash('Outcomes published successfully.')
                    return redirect(
                        url_for('admin_scores', assessment_id=aid) + '#outcome'
                    )

        # --- LOAD SELECTED ASSESSMENT ON GET or POST ---
        sid = request.values.get('assessment_id')  # works for ?assessment_id=... and form POST
        if sid:
            selected_assessment = Assessment.query.get(sid)
            if selected_assessment:
                raw_scores = (
                    db.session.query(Score, Assessor, Application, Criteria)
                    .join(Assessor, Score.assessor_id == Assessor.id)
                    .join(Application, Score.application_id == Application.id)
                    .join(Criteria, Score.criteria_id == Criteria.id)
                    .filter(Assessor.assessment_id == selected_assessment.id)
                    .all()
                )

        # --- Build tables as before ---
        detailed_scores = []
        # Group responses by application to compute summary (grouped by KEY)
        grouped = {}
        
        for score, assessor, application, criteria in raw_scores:
            weighted = (score.score * criteria.weight) / 100
            detailed_scores.append((score, assessor, application, criteria, weighted))
            app_key = application.id  # grouping by application id (KEY)
            if app_key not in grouped:
                grouped[app_key] = {
                    "application": application,
                    "total_weighted": 0,
                    "assessors": set(),
                    "count": 0
                }
            grouped[app_key]["total_weighted"] += weighted
            grouped[app_key]["count"] += 1
            grouped[app_key]["assessors"].add(assessor.id) 
        
        grouped_list = []
        for g in grouped.values():
            num_assessors = len(g["assessors"])
            # average weighted per assessor (1–10), then scale to 0–100
            if num_assessors:
                final_score = (g["total_weighted"] / num_assessors) * 10
            else:
                final_score = 0
            g["final_score"] = final_score
            grouped_list.append(g)

        # 2) sort by final_score descending
        grouped_list.sort(key=lambda x: x["final_score"], reverse=True)

        # 3) assign rank
        for idx, g in enumerate(grouped_list, start=1):
            g["rank"] = idx

        # now pass `grouped_scores=grouped_list` into the template
        return render_template(
            'admin_scores.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            detailed_scores=detailed_scores,
            grouped_scores=grouped_list
        )
    
    @app.route('/admin/edit-score/<int:score_id>', methods=['POST'])
    @admin_login_required
    def edit_score(score_id):
        s = Score.query.get_or_404(score_id)
        aid = s.assessor.assessment_id

        try:
            new_score   = int(request.form.get('score'))
            new_comment = request.form.get('comment')
            if not (0 <= new_score <= 10):
                flash("Score must be between 0 and 10.")
                return redirect(url_for('admin_scores', assessment_id=aid))

            next_ver = (ScoreHistory.query.filter_by(score_id=s.id).count() + 1)
            db.session.add(ScoreHistory(
                score_id=s.id,
                assessor_id=s.assessor_id,
                application_id=s.application_id,
                criteria_id=s.criteria_id,
                previous_score=s.score,
                previous_comment=s.comment,
                previous_finalised=s.finalised,
                action='admin_edit',
                version=next_ver
            ))

            s.score   = new_score
            s.comment = new_comment
            db.session.commit()
            flash(f"Score #{score_id} updated.")
        except Exception:
            db.session.rollback()
            flash("Error updating score.")
        return redirect(
            url_for('admin_scores', assessment_id=aid, _anchor=f'auditScores-{score_id}')
        )


    @app.route('/admin/scores/summary', methods=['GET', 'POST'])
    @admin_login_required
    def admin_scores_summary():
        assessments = Assessment.query.order_by(Assessment.name).all()

        selected_assessment = None
        criteria_list = []
        panel_breakdown_list = []
        app_breakdown_list = []

        aid = request.values.get('assessment_id')
        if aid:
            selected_assessment, criteria_list, panel_breakdown_list, app_breakdown_list = \
                build_scores_summary_context(int(aid))

        return render_template(
            'admin_scores_summary.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            panel_breakdown=panel_breakdown_list,
            app_breakdown=app_breakdown_list,
            criteria_list=criteria_list
        )

    
    @app.route('/admin/reopen-assessor/<int:assessor_id>', methods=['POST'])
    @admin_login_required
    def reopen_assessor(assessor_id):
        assessor = Assessor.query.get_or_404(assessor_id)
        aid = assessor.assessment_id

        scores = Score.query.filter_by(assessor_id=assessor_id).all()
        for s in scores:
            # next version number for this score
            next_ver = (ScoreHistory.query.filter_by(score_id=s.id).count() + 1)
            db.session.add(ScoreHistory(
                score_id=s.id,
                assessor_id=s.assessor_id,
                application_id=s.application_id,
                criteria_id=s.criteria_id,
                previous_score=s.score,
                previous_comment=s.comment,
                previous_finalised=s.finalised,
                action='reopen',
                version=next_ver
            ))
            s.finalised = False

        db.session.commit()
        flash(f"Reopened scoring for {assessor.name}. Previous state archived.")
        # pass assessment_id so page reloads with the same selection
        return redirect(url_for('admin_scores_summary', assessment_id=aid))

    @app.route('/admin/scores/publish', methods=['POST'])
    @admin_login_required
    def publish_scores():
        assessment_id = request.form.get('assessment_id')
        form_key      = request.form.get('form_key')
        report_type   = request.form.get('report_type', 'grant')
        
        if not all([assessment_id, form_key]):
            return jsonify({"error": "Missing required fields"}), 400
        
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            return jsonify({"error":"Assessment not found"}), 404

        selected_assessment, criteria_list, panel_breakdown_list, app_breakdown_list = \
            build_scores_summary_context(int(assessment_id))

        if not selected_assessment:
            return jsonify({"error":"Assessment not found"}), 404

        # NEW: render the summary fragment as HTML to publish
        table_html = render_template(
            'admin_scores_summary_publish_fragment.html',
            selected_assessment=selected_assessment,
            criteria_list=criteria_list,
            panel_breakdown=panel_breakdown_list,
            app_breakdown=app_breakdown_list
        )


        # 1) auth
        token = get_token()
        if isinstance(token, dict) and token.get("error"):
            return jsonify(token), 500
        headers = {"Authorization": f"Bearer {token}"}

        # 2) find folio by key
        query = f"""
        {{
        folios(key:"{form_key}") {{
            nodes {{ key id title }}
        }}
        }}
        """
        qres = requests.post(GRAPHQL_URL, json={"query": query}, headers=headers)
        if qres.status_code != 200:
            return jsonify({"error":"Failed to query folio", "details": qres.text}), qres.status_code
        nodes = qres.json().get("data", {}).get("folios", {}).get("nodes", [])
        if not nodes:
            return jsonify({"error":"No folio found for the provided key"}), 400
        folio_id = nodes[0]["id"]

        # Prefix-specific report publishing fields. GPLAN and PREP2 use
        # different Folio field IDs for the same outcome columns.
        publish_field_envs = {
            "GPLAN": {
                "provider": "FOLIO_FIELD_ID_GRANT_PROVIDER",
                "rank": "FOLIO_FIELD_ID_GRANT_RANK",
                "final_score": "FOLIO_FIELD_ID_GRANT_FINAL_SCORE",
                "funding_requested": "FOLIO_FIELD_ID_GRANT_FUNDING_REQUESTED",
                "funding_granted": "FOLIO_FIELD_ID_GRANT_FUNDING_GRANTED",
                "success": "FOLIO_FIELD_ID_GRANT_SUCCESS",
                "success_yes": "FOLIO_ANSWER_ID_GRANT_SUCCESS_YES",
                "success_no": "FOLIO_ANSWER_ID_GRANT_SUCCESS_NO",
                "table_html": "FOLIO_FIELD_ID_GPLAN_TABLE_HTML",
            },
            "PREP2": {
                "provider": "FOLIO_FIELD_ID_PROC_PROVIDER",
                "rank": "FOLIO_FIELD_ID_PROC_RANK",
                "final_score": "FOLIO_FIELD_ID_PROC_FINAL_SCORE",
                "funding_requested": "FOLIO_FIELD_ID_PROC_FUNDING_REQUESTED",
                "funding_granted": "FOLIO_FIELD_ID_PROC_FUNDING_GRANTED",
                "success": "FOLIO_FIELD_ID_PROC_SUCCESS",
                "success_yes": "FOLIO_ANSWER_ID_PROC_SUCCESS_YES",
                "success_no": "FOLIO_ANSWER_ID_PROC_SUCCESS_NO",
                "table_html": "FOLIO_FIELD_ID_PROC_TABLE_HTML",
            },
        }
        report_type_fallbacks = {
            "grant": "GPLAN",
            "gplan": "GPLAN",
            "procurement": "PREP2",
            "proc": "PREP2",
            "prep2": "PREP2",
        }
        normalized_form_key = (form_key or "").strip().upper()
        publish_prefix = next(
            (prefix for prefix in publish_field_envs if normalized_form_key.startswith(prefix)),
            None
        )
        if not publish_prefix:
            publish_prefix = report_type_fallbacks.get((report_type or "").strip().lower())
        if not publish_prefix:
            return jsonify({
                "error": "Unsupported Folio key prefix",
                "details": "Expected a GPLAN or PREP2 Folio key prefix."
            }), 400

        field_envs = publish_field_envs[publish_prefix]
        field_ids = {name: os.environ.get(env_name) for name, env_name in field_envs.items()}

        missing = [
            env_name
            for name, env_name in field_envs.items()
            if not field_ids.get(name)
        ]
        if missing:
            return jsonify({"error":"Missing .env mappings", "fields": missing}), 400

        # Recompute Outcome Summary (rank & final score)
        assessment = Assessment.query.get(assessment_id)
        if not assessment:
            return jsonify({"error":"Assessment not found"}), 404

        raw_scores = (
            db.session.query(Score, Assessor, Application, Criteria)
            .join(Assessor, Score.assessor_id == Assessor.id)
            .join(Application, Score.application_id == Application.id)
            .join(Criteria, Score.criteria_id == Criteria.id)
            .filter(Assessor.assessment_id == assessment.id)
            .all()
        )

        grouped = {}
        for s, a, app, c in raw_scores:
            w = (s.score * c.weight) / 100.0  # 0..10
            g = grouped.setdefault(app.id, {
                "application": app,
                "total_weighted": 0.0,
                "assessors": set(),
                "count": 0
            })
            g["total_weighted"] += w
            g["count"] += 1
            g["assessors"].add(a.id)

        grouped_list = []
        for g in grouped.values():
            na = len(g["assessors"])
            final_score = (g["total_weighted"]/na)*10 if na else 0.0  # 0..100
            g["final_score"] = final_score
            grouped_list.append(g)

        grouped_list.sort(key=lambda x: x["final_score"], reverse=True)
        for idx, g in enumerate(grouped_list, start=1):
            g["rank"] = idx

        # Build fieldResponses with rowIndex
        def resp_text(field_id, text, rowIndex=None):
            return f'{{fieldId:"{field_id}", text:{json.dumps(text)}' + (f', rowIndex:{rowIndex}' if rowIndex is not None else '') + '}'

        def resp_numeric(field_id, num, rowIndex=None):
            # GraphQL numeric literal, not quoted
            return f'{{fieldId:"{field_id}", numeric:{num}' + (f', rowIndex:{rowIndex}' if rowIndex is not None else '') + '}'

        def resp_select(field_id, answer_id, rowIndex=None):
            return (
                f'{{fieldId:"{field_id}", fieldAnswerResponses:[{{fieldAnswerId:"{answer_id}"}}]' +
                (f', rowIndex:{rowIndex}' if rowIndex is not None else '') + '}'
            )

        frags = []
        for i, g in enumerate(grouped_list):
            app = g["application"]
            provider = _clean_provider_name(app.code)
            final_score = round(g["final_score"], 2)

            frags.append(resp_text(field_ids["provider"], provider, rowIndex=i))
            frags.append(resp_numeric(field_ids["rank"], g["rank"], rowIndex=i))
            frags.append(resp_numeric(field_ids["final_score"], final_score, rowIndex=i))

            if app.funding_requested is not None:
                frags.append(resp_numeric(field_ids["funding_requested"], float(app.funding_requested), rowIndex=i))
            if app.funding_given is not None:
                frags.append(resp_numeric(field_ids["funding_granted"], float(app.funding_given), rowIndex=i))

            success_answer = field_ids["success_yes"] if app.successful else field_ids["success_no"]
            frags.append(resp_select(field_ids["success"], success_answer, rowIndex=i))

        # Push the outcome HTML to the report-specific rich text field.
        frags.append(resp_text(field_ids["table_html"], table_html))

        field_responses_str = "[\n  " + ",\n  ".join(frags) + "\n]"

        mutation = f"""
        mutation {{
        updateFolio(
            input: {{
            folioId: "{folio_id}",
            fieldResponses: {field_responses_str}
            }}
        ) {{
            data {{ id key title }}
            errors {{ message }}
        }}
        }}
        """
        mres = requests.post(GRAPHQL_URL, json={"query": mutation}, headers=headers)
        if mres.status_code != 200:
            return jsonify({"error":"Failed to update folio", "details": mres.text}), mres.status_code

        result = json.dumps(mres.json(), indent=2)
        return render_template('publish_result.html', result=result)

    
    @app.route('/admin/assessors', methods=['GET', 'POST'])
    @admin_login_required
    def admin_assessors():
        # Query all assessments to populate the dropdown.
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected_assessment = None
        assessors = []
        if request.method == 'POST':
            selected_assessment_id = request.form.get('assessment_id')
            if selected_assessment_id:
                selected_assessment = Assessment.query.get(selected_assessment_id)
                assessors = Assessor.query.filter_by(assessment_id=selected_assessment.id).all()
        return render_template(
            'admin_assessors.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            assessors=assessors
        )

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

    @app.route('/score/<token>/login', methods=['GET', 'POST'])
    def assessor_login(token):
        assessor = Assessor.query.filter_by(unique_token=token).first()
        if not assessor:
            return "Invalid URL", 404

        if request.method == 'POST':
            entered_code = request.form.get('access_code')
            if entered_code == assessor.access_code:
                # Store assessor id in session and redirect to scoring page
                session['assessor_id'] = assessor.id
                return redirect(url_for('score', token=token))
            else:
                flash("Invalid access code. Please try again.")
        return render_template('assessor_login.html', token=token)


    @app.route('/score/<token>', methods=['GET', 'POST'])
    def score(token):
        assessor = Assessor.query.filter_by(unique_token=token).first()
        if not assessor:
            return "Invalid URL", 404

        if 'assessor_id' not in session or session['assessor_id'] != assessor.id:
            return redirect(url_for('assessor_login', token=token))

        if request.method == 'POST':
            action = request.form.get('action')  # will be 'save' or 'finalise'

        # Get the assessment via the assessor relationship
        assessment = Assessment.query.get(assessor.assessment_id)
        # Use the relationships defined in your models (if set up) or query explicitly:
        applications = Application.query.filter_by(assessment_id=assessment.id).all()
        criteria = Criteria.query.filter_by(assessment_id=assessment.id).all()

        # Query existing scores for this assessor (if any)
        existing_scores = Score.query.filter_by(assessor_id=assessor.id).all()
        score_dict = {}
        for s in existing_scores:
            key = f"{s.application_id}-{s.criteria_id}"
            score_dict[key] = s

        # NEW: if any of this assessor’s scores are finalised, we treat the whole
        #     submission as final
        is_finalised = any(s.finalised for s in existing_scores)

        if request.method == 'POST':
            for app_entry in applications:
                for crit in criteria:
                    field_name = f"score-{app_entry.id}-{crit.id}"
                    score_value = request.form.get(field_name)
                    comment_field = f"comment-{app_entry.id}-{crit.id}"
                    comment = request.form.get(comment_field)
                    # Only process if a score value is provided.
                    if score_value:
                        try:
                            score_int = int(score_value)
                            if 0 <= score_int <= 10:
                                key = f"{app_entry.id}-{crit.id}"
                                if key in score_dict:
                                    existing = score_dict[key]
                                    existing.score = score_int
                                    existing.comment = comment
                                else:
                                    new_score = Score(
                                        assessor_id=assessor.id,
                                        application_id=app_entry.id,
                                        criteria_id=crit.id,
                                        score=score_int,
                                        comment=comment
                                    )
                                    db.session.add(new_score)
                            else:
                                flash("Score must be between 0 and 10.")
                                return redirect(url_for('score', token=token))
                        except ValueError:
                            flash("Invalid score input.")
                            return redirect(url_for('score', token=token))
            # if they clicked “Submit and finalise…”
            if action == 'finalise':
                # mark every one of this assessor’s scores as final
                for s in Score.query.filter_by(assessor_id=assessor.id):
                    s.finalised = True

            db.session.commit()
            # flash feedback for the modal
            if action == 'save':
                flash('Your progress has been saved. You can come back to this submission at any time and continue editing. Simply use the link that was provided by the admin to log back in and access the evaluation portal')
            elif action == 'finalise':
                flash('Your scores have been finalised and submitted. You can return to the portal at any time to view your final scores.')
            return redirect(url_for('score', token=token))


        # --- new: compute weighted totals for each application ---
        weighted_scores = {}
        for app_entry in applications:
            total = 0
            for crit in criteria:
                key = f"{app_entry.id}-{crit.id}"
                if key in score_dict:
                    # note: score_dict[key].score is the integer 0–10
                    total += (score_dict[key].score * crit.weight) / 10
            # round or int‐cast as you prefer
            weighted_scores[app_entry.id] = round(total, 2)

        crit_weights = { c.id: c.weight for c in criteria }

        return render_template(
            'score.html',
            token=token,
            assessment=assessment,
            applications=applications,
            criteria=criteria,
            score_dict=score_dict,
            crit_weights=crit_weights,
            weighted_scores=weighted_scores,
            is_finalised=is_finalised
        )

    @app.route('/score/<token>/report.pdf', methods=['GET', 'POST'])
    def score_report_pdf(token):
        assessor = Assessor.query.filter_by(unique_token=token).first()
        if not assessor:
            return "Invalid URL", 404

        if 'assessor_id' not in session or session['assessor_id'] != assessor.id:
            return redirect(url_for('assessor_login', token=token))

        assessment = Assessment.query.get(assessor.assessment_id)
        applications = Application.query.filter_by(assessment_id=assessment.id).all()
        criteria = Criteria.query.filter_by(assessment_id=assessment.id).all()
        existing_scores = Score.query.filter_by(assessor_id=assessor.id).all()
        score_dict = {
            f"{score.application_id}-{score.criteria_id}": score
            for score in existing_scores
        }

        pdf_io = build_individual_scores_pdf(
            assessor=assessor,
            assessment=assessment,
            applications=applications,
            criteria=criteria,
            score_dict=score_dict,
            form=request.form if request.method == 'POST' else None
        )
        filename = safe_download_filename(
            f"Individual Panel Scores - {assessor.name} - {assessment.name}.pdf"
        )
        pdf_io.seek(0)
        return send_file(
            pdf_io,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    @app.route('/admin/scores/summary-history', methods=['GET', 'POST'])
    @admin_login_required
    def admin_scores_summary_history():
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected_assessment = None
        criteria_list = []
        app_breakdown_list = []
        old_weights_map = {}  # key: "assessorId-appId-critId" -> previous weighted (0..10)

        aid = request.values.get('assessment_id')
        if not aid:
            return render_template(
                'admin_scores_summary_history.html',
                assessments=assessments,
                selected_assessment=None,
                criteria_list=[],
                app_breakdown=[],
                old_weights_map={}
            )

        selected_assessment = Assessment.query.get(aid)
        if not selected_assessment:
            flash("Assessment not found.")
            return render_template(
                'admin_scores_summary_history.html',
                assessments=assessments,
                selected_assessment=None,
                criteria_list=[],
                app_breakdown=[],
                old_weights_map={}
            )

        # Criteria for headers and weight map
        criteria_list = (Criteria.query
                        .filter_by(assessment_id=selected_assessment.id)
                        .order_by(Criteria.id).all())
        crit_weight = {c.id: c.weight for c in criteria_list}

        # Current scores (as in your summary)
        raw_scores = (
            db.session.query(Score, Assessor, Application, Criteria)
            .join(Assessor, Score.assessor_id == Assessor.id)
            .join(Application, Score.application_id == Application.id)
            .join(Criteria, Score.criteria_id == Criteria.id)
            .filter(Assessor.assessment_id == selected_assessment.id)
            .all()
        )

        # Build application-centric breakdown with per-criterion weights (current)
        app_breakdown = {}
        score_ids = []
        for s, assessor, application, criteria in raw_scores:
            score_ids.append(s.id)
            w = (s.score * criteria.weight) / 100.0  # 0..10
            entry = app_breakdown.setdefault(application.id, {
                "application": application,
                "assessors": {}
            })
            row = entry["assessors"].setdefault(assessor.id, {
                "assessor": assessor,
                "weights": {},         # crit.id -> current weighted (0..10)
                "total_weighted": 0.0  # sum of current weighted (0..10)
            })
            row["weights"][criteria.id] = w
            row["total_weighted"] += w

        # Flatten + compute app average (current)
        for entry in app_breakdown.values():
            rows = list(entry["assessors"].values())
            avg_w = (sum(r["total_weighted"] for r in rows) / len(rows)) if rows else 0.0
            app_breakdown_list.append({
                "application":  entry["application"],
                "assessors":    rows,
                "avg_weighted": avg_w
            })
        # Sort apps by average desc (or by code/id if you prefer)
        app_breakdown_list.sort(key=lambda x: x["avg_weighted"], reverse=True)

        # Build previous weighted map from ScoreHistory (latest version per score_id)
        if score_ids:
            histories = ScoreHistory.query.filter(ScoreHistory.score_id.in_(score_ids)).all()
            latest_by_score = {}
            for h in histories:
                prev = latest_by_score.get(h.score_id)
                if (prev is None) or (h.version > prev.version) or (
                    h.version == prev.version and getattr(h, 'changed_at', None) and getattr(prev, 'changed_at', None) and h.changed_at > prev.changed_at
                ):
                    latest_by_score[h.score_id] = h

            for h in latest_by_score.values():
                wt = crit_weight.get(h.criteria_id, 0)  # %
                old_w = (h.previous_score * wt) / 100.0  # 0..10
                key = f"{h.assessor_id}-{h.application_id}-{h.criteria_id}"
                old_weights_map[key] = old_w

        return render_template(
            'admin_scores_summary_history.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            criteria_list=criteria_list,
            app_breakdown=app_breakdown_list,
            old_weights_map=old_weights_map
        )

    @app.route('/admin/scores/summary-compare', methods=['GET', 'POST'])
    @admin_login_required
    def admin_scores_summary_compare():
        assessments = Assessment.query.order_by(Assessment.name).all()

        selected_assessment = None
        criteria_list = []
        assessors_list = []
        compare_rows = []

        aid = request.values.get('assessment_id')
        if aid:
            selected_assessment = Assessment.query.get(aid)

            criteria_list = (Criteria.query
                            .filter_by(assessment_id=selected_assessment.id)
                            .order_by(Criteria.id)
                            .all())

            raw_scores = (
                db.session.query(Score, Assessor, Application, Criteria)
                .join(Assessor, Score.assessor_id == Assessor.id)
                .join(Application, Score.application_id == Application.id)
                .join(Criteria, Score.criteria_id == Criteria.id)
                .filter(Assessor.assessment_id == selected_assessment.id)
                .all()
            )

            # --- collect assessors + applications ---
            assessors_by_id = {}
            apps_by_id = {}

            # app_totals[app_id][assessor_id] = total_weighted_score (0..10 overall scale)
            app_totals = defaultdict(lambda: defaultdict(float))

            # optional: completeness counters if you want later
            app_crit_count = defaultdict(lambda: defaultdict(int))  # app_id -> assessor_id -> count
            total_criteria = len(criteria_list)

            for score, assessor, application, criteria in raw_scores:
                assessors_by_id[assessor.id] = assessor
                apps_by_id[application.id] = application

                # weighted contribution on 0..10 scale overall
                # (score is 0..10, weights sum to 100 => overall total ends up 0..10)
                w = (score.score * criteria.weight) / 100.0

                app_totals[application.id][assessor.id] += w
                app_crit_count[application.id][assessor.id] += 1

            # stable assessor ordering (pick whichever field you have: name, last_name etc.)
            assessors_list = sorted(
                assessors_by_id.values(),
                key=lambda a: (getattr(a, "name", "") or "", a.id)
            )

            # --- overall averages per app ---
            overall_by_app = {}
            for app_id, application in apps_by_id.items():
                scores = [app_totals[app_id].get(a.id) for a in assessors_list if a.id in app_totals[app_id]]
                overall_avg = (sum(scores) / len(scores)) if scores else 0
                overall_by_app[app_id] = overall_avg

            # --- ranking helpers (dense ranking: 1,1,2,3...) ---
            def dense_rank(sorted_items):
                """
                sorted_items: list of tuples (key, score) already sorted desc by score
                returns dict key->rank
                """
                ranks = {}
                last_score = None
                rank = 0
                for i, (k, s) in enumerate(sorted_items):
                    if last_score is None or s != last_score:
                        rank += 1
                        last_score = s
                    ranks[k] = rank
                return ranks

            # overall ranks
            overall_sorted = sorted(overall_by_app.items(), key=lambda kv: kv[1], reverse=True)
            overall_ranks = dense_rank(overall_sorted)

            # per-assessor ranks
            assessor_ranks = {}
            for a in assessors_list:
                items = []
                for app_id in apps_by_id.keys():
                    # if an assessor never scored that app, you can treat as None or 0
                    # I’d treat missing as None so it’s obvious it’s incomplete.
                    if a.id in app_totals[app_id]:
                        items.append((app_id, app_totals[app_id][a.id]))
                items.sort(key=lambda kv: kv[1], reverse=True)
                assessor_ranks[a.id] = dense_rank(items)

            # --- build rows in overall-ranked order ---
            for app_id, overall_avg in overall_sorted:
                application = apps_by_id[app_id]
                row = {
                    "application": application,
                    "overall_score": overall_avg,
                    "overall_rank": overall_ranks.get(app_id),
                    "assessors": []
                }

                for a in assessors_list:
                    has_score = a.id in app_totals[app_id]
                    row["assessors"].append({
                        "assessor": a,
                        "score": app_totals[app_id].get(a.id),                 # float or None
                        "rank": assessor_ranks.get(a.id, {}).get(app_id),      # int or None
                        "complete": (app_crit_count[app_id].get(a.id, 0) == total_criteria),
                        "count": app_crit_count[app_id].get(a.id, 0),
                        "total": total_criteria
                    })

                compare_rows.append(row)

        return render_template(
            'admin_scores_summary_compare.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            criteria_list=criteria_list,
            assessors_list=assessors_list,
            compare_rows=compare_rows
        )

    @app.route('/score/<token>/autosave', methods=['POST'])
    def autosave_score(token):
        assessor = Assessor.query.filter_by(unique_token=token).first_or_404()
        if session.get('assessor_id') != assessor.id:
            return jsonify({ 'error': 'not-authorized' }), 401

        data = request.get_json() or {}
        app_id  = data.get('application_id')
        crit_id = data.get('criteria_id')
        score_v = data.get('score')
        comment = data.get('comment')

        if app_id is None or crit_id is None:
            return jsonify({ 'error': 'missing parameters' }), 400

        # coerce score if present
        s = Score.query.filter_by(
            assessor_id=assessor.id,
            application_id=app_id,
            criteria_id=crit_id
        ).first()

        # parse int if nonempty
        if score_v is not None and score_v != '':
            try:
                score_i = int(score_v)
                if not (0 <= score_i <= 10):
                    raise ValueError
            except ValueError:
                return jsonify({ 'error': 'invalid score' }), 400
        else:
            score_i = None

        if s:
            # update existing
            if score_i is not None:
                s.score = score_i
            if comment is not None:
                s.comment = comment
        else:
            # only create if at least one field present
            s = Score(
                assessor_id   = assessor.id,
                application_id= app_id,
                criteria_id   = crit_id,
                score         = score_i or 0,
                comment       = comment or ''
            )
            db.session.add(s)

        db.session.commit()
        return jsonify({ 'status': 'ok' })

    ## Now add the contact verification process
    # Route to generate an obfuscated token from a folio key (for admin use)
    @app.route("/generate/<folio_key>")
    @admin_login_required
    def generate_token(folio_key):
        token = serializer.dumps(folio_key)
        return f"Token for {folio_key}: <a href='/link/{token}'>/link/{token}</a>"

    # New route that uses a token (instead of a plain folio key) in the URL.
    @app.route("/link/<token>")
    def folio_page(token):
        try:
            # Decode the token to retrieve the original folio key.
            folio_key = serializer.loads(token)
        except Exception as e:
            return f"Invalid token: {str(e)}", 400

        token_api = get_token()
        if isinstance(token_api, dict) and token_api.get("error"):
            return f"Error fetching token: {token_api['error']}", 500

        headers = {"Authorization": f"Bearer {token_api}"}

        # Query for the entity using the folio key.
        query_entity = """
        query GetEntity($folioKey: String!) {
        folios(key: $folioKey) {
            nodes {
            entities {
                nodes {
                id
                name
                }
            }
            }
        }
        }
        """
        variables = {"folioKey": folio_key}
        res_entity = requests.post(
            GRAPHQL_URL,
            json={"query": query_entity, "variables": variables},
            headers=headers
        )

        if res_entity.status_code != 200:
            return f"Error fetching folio: {res_entity.text}", res_entity.status_code

        data_entity = res_entity.json()
        try:
            entity = data_entity["data"]["folios"]["nodes"][0]["entities"]["nodes"][0]
            entity_id = entity["id"]
        except (KeyError, IndexError):
            return f"Entity not found for folio key: {folio_key}", 404

        # Query for contacts using the entity's ID.
        query_contacts = """
        query GetContacts($entityIds: [ID!]!) {
        contacts(first: 10, entityIds: $entityIds) {
            edges {
            node {
                id
                name
                telephone
                email
            }
            }
        }
        }
        """
        variables = {"entityIds": [entity_id]}
        res_contacts = requests.post(
            GRAPHQL_URL,
            json={"query": query_contacts, "variables": variables},
            headers=headers
        )

        if res_contacts.status_code != 200:
            return f"Error fetching contacts: {res_contacts.text}", res_contacts.status_code

        data_contacts = res_contacts.json()
        try:
            contacts = [edge["node"] for edge in data_contacts["data"]["contacts"]["edges"]]
        except (KeyError, TypeError):
            contacts = []

        return render_template("folio.html", folio_key=folio_key, entity=entity, contacts=contacts)
    
    @app.template_filter('clean_code')
    def clean_code(s):
        # 1) strip leading digits+colon+space, then
        # 2) strip anything from "(" onward
        s = re.sub(r'^\d+:\s*', '', s)
        s = re.sub(r'\s*\(.*$',   '', s)
        return s
    
    @app.template_filter('clean_code_no')
    def clean_code(s):
        # 1) strip anything from ":" onward
        s = re.sub(r'\s*\:.*$',   '', s)
        return s

    # Create the database tables within the application context
    with app.app_context():
        #db.drop_all()
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
