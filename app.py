# app.py
import os, secrets, time, requests, json
from flask import Flask, session, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from extensions import db
from functools import wraps
import models
import time
from itsdangerous import URLSafeSerializer
from datetime import timedelta
from werkzeug.utils import secure_filename

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'XXX'  # Replace with a strong secret key
    app.config['ADMIN_KEYPHRASE'] = 'XXX'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    serializer = URLSafeSerializer(app.config['SECRET_KEY'])
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
                "https://hncoriginal.sandbox.usefolio.com/oauth/token",
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

    def admin_login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_authenticated'):
                # Redirect to a login page and pass the next parameter so you can redirect back after login.
                return redirect(url_for('admin_login', next=request.url))
            return f(*args, **kwargs)
        return decorated_function

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            keyphrase = request.form.get('keyphrase')
            if keyphrase == app.config.get('ADMIN_KEYPHRASE', 'your_default_keyphrase'):
                session['admin_authenticated'] = True
                session.permanent = True
                flash("Logged in successfully!")
                next_url = request.args.get('next')
                return redirect(next_url or url_for('admin'))
            else:
                flash("Invalid keyphrase. Please try again.")
                return redirect(url_for('admin_login'))
        return render_template('admin_login.html')

    @app.route('/')
    def index():
        return render_template('index.html')


    @app.route('/admin', methods=['GET', 'POST'])
    @admin_login_required
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
            
            # Process 2nd PDF Upload (if needed)
            pdf_score = request.files.get('pdf_file_score')
            if pdf_score:
                filename = secure_filename(pdf_score.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                pdf_score.save(filepath)
                new_assessment.pdf_score_filename = filename


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
    @admin_login_required
    def admin_scores():
        assessments = Assessment.query.order_by(Assessment.name).all()
        selected_assessment = None
        raw_scores = []
        
        if request.method == 'POST':
            selected_assessment_id = request.form.get('assessment_id')
            if selected_assessment_id:
                selected_assessment = Assessment.query.get(selected_assessment_id)
                raw_scores = (
                    db.session.query(Score, Assessor, Application, Criteria)
                    .join(Assessor, Score.assessor_id == Assessor.id)
                    .join(Application, Score.application_id == Application.id)
                    .join(Criteria, Score.criteria_id == Criteria.id)
                    .filter(Assessor.assessment_id == selected_assessment.id)
                    .all()
                )
        
        # Detailed scores list (for original table)
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
        
        # Sorted grouped list: highest total score first.
        grouped_scores = sorted(grouped.values(), key=lambda x: x["total_weighted"], reverse=True)
        
        return render_template(
            'admin_scores.html',
            assessments=assessments,
            selected_assessment=selected_assessment,
            detailed_scores=detailed_scores,
            grouped_scores=grouped_scores
        )
    
    @app.route('/admin/scores/publish', methods=['POST'])
    @admin_login_required
    def publish_scores():
        # Get data from the publish form:
        assessment_id = request.form.get('assessment_id')
        form_key = request.form.get('form_key')
        round_field_id = request.form.get('round')  # New: selected round's field ID
        table_html = request.form.get('table_html')

        if not all([assessment_id, form_key, round_field_id, table_html]):
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
        mutation = f"""
        mutation {{
        updateFolio(
            input: {{
            folioId: "{folio_id}",
            fieldResponses: [
                {{
                fieldId: "{round_field_id}", 
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

        # Pretty-print the JSON response.
        result = json.dumps(mutation_response.json(), indent=2)
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
                            if 1 <= score_int <= 10:
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
                                flash("Score must be between 1 and 10.")
                                return redirect(url_for('score', token=token))
                        except ValueError:
                            flash("Invalid score input.")
                            return redirect(url_for('score', token=token))
            db.session.commit()
            flash("Progress saved!")  # or "Scores submitted successfully!" as appropriate.
            return redirect(url_for('score', token=token))
            
        return render_template(
            'score.html',
            token=token,
            assessment=assessment,
            applications=applications,
            criteria=criteria,
            score_dict=score_dict
        )

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


    # Create the database tables within the application context
    with app.app_context():
        #db.drop_all()
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
