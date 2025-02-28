# app.py
import os, secrets, time, requests, json
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from extensions import db
import models
from werkzeug.utils import secure_filename

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'XXX'  # Replace with a strong secret key
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scoring.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'uploads'
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    TOKEN_INFO = {"access_token": None, "expires_at": 0}
    GRAPHQL_URL = "XXX"
    
    # Initialize the shared SQLAlchemy instance with this app
    db.init_app(app)
    
    # Import models after db.init_app to ensure they are registered
    from models import Application, Criteria, Assessor, Score, Assessment

    def get_token():
        """Fetch a new token if expired or missing."""
        if not TOKEN_INFO["access_token"] or time.time() >= TOKEN_INFO["expires_at"]:
            print("Fetching new token...")
            response = requests.post(
                "https://XXX/oauth/token",
                data={
                    "client_id": "XXX",
                    "client_secret": "XXX",
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

    @app.route('/')
    def index():
        return render_template('index.html')


    @app.route('/admin', methods=['GET', 'POST'])
    def admin():
        from werkzeug.utils import secure_filename  # Ensure this is imported
        if request.method == 'POST':
            # Create a new assessment session first
            assessment_name = request.form.get('assessment_name')
            if not assessment_name:
                flash("Please provide an assessment name.")
                return redirect(url_for('admin'))
            
            new_assessment = Assessment(name=assessment_name)
            db.session.add(new_assessment)
            db.session.commit()  # Commit to get new_assessment.id

            # Process Application Codes (tied to this assessment)
            apps_raw = request.form.get('applications')
            if apps_raw:
                for line in apps_raw.strip().splitlines():
                    code = line.strip()
                    if code and not Application.query.filter_by(code=code, assessment_id=new_assessment.id).first():
                        db.session.add(Application(code=code, assessment_id=new_assessment.id))
            
            # Process Criteria (tied to this assessment)
            criteria_raw = request.form.get('criteria')
            if criteria_raw:
                for line in criteria_raw.strip().splitlines():
                    parts = line.split('|')
                    if len(parts) == 2:
                        description = parts[0].strip()
                        try:
                            weight = float(parts[1].strip())
                            db.session.add(Criteria(description=description, weight=weight, assessment_id=new_assessment.id))
                        except ValueError:
                            pass  # handle invalid weight

            # Process PDF Upload (if needed)
            pdf = request.files.get('pdf_file')
            if pdf:
                filename = secure_filename(pdf.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                pdf.save(filepath)
                new_assessment.pdf_filename = filename
            
            # Process Assessors (tied to this assessment)
            assessors_raw = request.form.get('assessors')
            if assessors_raw:
                for line in assessors_raw.strip().splitlines():
                    name = line.strip()
                    if name:
                        token = secrets.token_urlsafe(16)
                        access_code = secrets.token_hex(4)
                        assessor = Assessor(name=name, unique_token=token, access_code=access_code, assessment_id=new_assessment.id)
                        db.session.add(assessor)
            
            db.session.commit()
            flash("Data submitted successfully!")
            # Redirect with assessment_id so that the admin page shows only this session’s assessors.
            return redirect(url_for('admin', assessment_id=new_assessment.id))
        
        # On GET, if an assessment_id is provided, show only that assessment's assessors.
        assessment_id = request.args.get('assessment_id')
        assessors = []
        if assessment_id:
            assessors = Assessor.query.filter_by(assessment_id=assessment_id).all()
        return render_template('admin.html', assessors=assessors)

    @app.route('/admin/scores', methods=['GET', 'POST'])
    def admin_scores():
        # Get all assessments to populate the dropdown.
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected_assessment = None
        raw_scores = []
        
        if request.method == 'POST':
            selected_assessment_id = request.form.get('assessment_id')
            if selected_assessment_id:
                selected_assessment = Assessment.query.get(selected_assessment_id)
                # Join Score with Assessor, Application, and Criteria,
                # but restrict to those tied to the selected assessment.
                raw_scores = (
                    db.session.query(Score, Assessor, Application, Criteria)
                    .join(Assessor, Score.assessor_id == Assessor.id)
                    .join(Application, Score.application_id == Application.id)
                    .join(Criteria, Score.criteria_id == Criteria.id)
                    .filter(Assessor.assessment_id == selected_assessment.id)
                    .all()
                )
        scores = []
        for score, assessor, application, criteria in raw_scores:
            weighted = (score.score * criteria.weight)/100
            scores.append((score, assessor, application, criteria, weighted))


        return render_template(
            'admin_scores.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            scores=scores
        )
    
    @app.route('/admin/scores/publish', methods=['POST'])
    def publish_scores():
        # Get data from the publish form:
        assessment_id = request.form.get('assessment_id')
        form_key = request.form.get('form_key')
        table_html = request.form.get('table_html')

        if not all([assessment_id, form_key, table_html]):
            return jsonify({"error": "Missing required fields"}), 400

        # Get an API token
        token = get_token()
        if isinstance(token, dict) and token.get("error"):
            return jsonify(token), 500

        headers = {"Authorization": f"Bearer {token}"}

        # 1. Query the API for the folio ID using the provided form key.
        query = f"""
        {{
        folios(key:"{form_key}") {{
            nodes {{
            key
            id
            title
            }}
        }}
        }}
        """
        query_response = requests.post(
            GRAPHQL_URL,
            json={"query": query},
            headers=headers
        )
        if query_response.status_code != 200:
            return jsonify({"error": "Failed to query folio", "details": query_response.text}), query_response.status_code
        data = query_response.json()
        nodes = data.get("data", {}).get("folios", {}).get("nodes", [])
        if not nodes:
            return jsonify({"error": "No folio found for the provided key"}), 400
        folio_id = nodes[0]["id"]

        # 2. Send the mutation to update the folio with the table HTML.
        # Note: json.dumps(table_html) ensures that any quotes in the HTML are escaped.
        mutation = f"""
        mutation {{
        updateFolio(
            input: {{
            folioId: "{folio_id}",
            fieldResponses: [
                {{
                fieldId: "XXX", 
                text: {json.dumps(table_html)}
                }}
            ]
            }}
        ) {{
            data {{
            id
            key
            title
            }}
        }}
        }}
        """
        mutation_response = requests.post(
            GRAPHQL_URL,
            json={"query": mutation},
            headers=headers
        )
        if mutation_response.status_code != 200:
            return jsonify({"error": "Failed to update folio", "details": mutation_response.text}), mutation_response.status_code

        return jsonify(mutation_response.json())
    
    @app.route('/admin/assessors', methods=['GET', 'POST'])
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
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

        assessment_id = assessor.assessment_id
        # Fetch the assessment (so we can get the PDF filename)
        assessment = Assessment.query.get(assessment_id)
        applications = Application.query.filter_by(assessment_id=assessment_id).all()
        criteria = Criteria.query.filter_by(assessment_id=assessment_id).all()

        if request.method == 'POST':
            for app_entry in applications:
                for crit in criteria:
                    score_value = request.form.get(f"score-{app_entry.id}-{crit.id}")
                    comment = request.form.get(f"comment-{app_entry.id}-{crit.id}")
                    if score_value:
                        try:
                            score_int = int(score_value)
                            if 1 <= score_int <= 10:
                                new_score = Score(
                                    assessor_id=assessor.id,
                                    application_id=app_entry.id,
                                    criteria_id=crit.id,
                                    score=score_int,
                                    comment=comment
                                )
                                db.session.add(new_score)
                            else:
                                flash("Score must be between 1 and 10.")
                                return redirect(url_for('score', token=token))
                        except ValueError:
                            flash("Invalid score input.")
                            return redirect(url_for('score', token=token))
            db.session.commit()
            flash("Scores submitted successfully!")
            return redirect(url_for('score', token=token))
            
        return render_template(
            'score.html',
            token=token,
            assessment=assessment,
            applications=applications,
            criteria=criteria
        )


    # Create the database tables within the application context
    with app.app_context():
        db.drop_all()
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
