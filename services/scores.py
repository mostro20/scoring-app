from extensions import db
from models import Application, Criteria, Assessor, Score, Assessment, ScoreHistory


def build_scores_summary_context(assessment_id: int):
    selected_assessment = Assessment.query.get(assessment_id)
    if not selected_assessment:
        return None, [], [], []

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

    # ---- Panel-member breakdown (same as your current code) ----
    panel_breakdown = {}
    for score, assessor, application, criteria in raw_scores:
        w = (score.score * criteria.weight) / 100
        entry = panel_breakdown.setdefault(assessor.id, {
            "assessor": assessor,
            "scores": [],
            "finalised": True
        })
        if not score.finalised:
            entry["finalised"] = False
        entry["scores"].append({
            "application": application,
            "criteria": criteria,
            "weighted": w,
            "comment": score.comment,
            "score": score.score,
        })

    for entry in panel_breakdown.values():
        entry["scores"].sort(key=lambda x: (x["application"].id, x["criteria"].id))

    panel_breakdown_list = list(panel_breakdown.values())

    # Group each assessor's rows by application for the accordion
    for pb in panel_breakdown_list:
        apps = {}
        for item in pb["scores"]:
            app_id = item["application"].id
            block = apps.setdefault(app_id, {
                "application": item["application"],
                "criteria_items": []
            })
            block["criteria_items"].append({
                "criteria": item["criteria"],
                "score": item["score"],
                "weighted": item["weighted"],
                "comment": item["comment"] or ""
            })
        for blk in apps.values():
            blk["criteria_items"].sort(key=lambda x: x["criteria"].id)
        pb["by_application"] = sorted(apps.values(), key=lambda x: x["application"].id)

    # ---- Application-centric breakdown (same as your current code) ----
    app_breakdown = {}
    app_breakdown_list = []

    for score, assessor, application, criteria in raw_scores:
        w = (score.score * criteria.weight) / 100
        entry = app_breakdown.setdefault(application.id, {
            "application": application,
            "assessors": {}
        })
        asc = entry["assessors"].setdefault(assessor.id, {
            "assessor": assessor,
            "weights": {},
            "total_weighted": 0
        })
        asc["weights"][criteria.id] = w
        asc["total_weighted"] += w

    for entry in app_breakdown.values():
        rows = list(entry["assessors"].values())
        avg_w = (sum(r["total_weighted"] for r in rows) / len(rows)) if rows else 0
        app_breakdown_list.append({
            "application": entry["application"],
            "assessors": rows,
            "avg_weighted": avg_w
        })
    app_breakdown_list.sort(key=lambda x: x["avg_weighted"], reverse=True)

    return selected_assessment, criteria_list, panel_breakdown_list, app_breakdown_list
