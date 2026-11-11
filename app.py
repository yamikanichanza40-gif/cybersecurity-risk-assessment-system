
from flask import Flask, render_template, request, redirect, url_for, flash
from database import initialize_db, get_db_connection, get_risk_register, get_dashboard_data

app = Flask(__name__)
app.secret_key = "cybersecurity_project_secret_key"

initialize_db()


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    # Retrieve live information from the SQLite database
    summary, risk_distribution, risks = get_dashboard_data()

    return render_template(
        "dashboard.html",
        summary=summary,
        distribution=risk_distribution,
        risks=risks
    )

# ==========================================
# ASSET MANAGEMENT - REGISTER AND VIEW
# ==========================================

@app.route("/assets", methods=["GET", "POST"])
def manage_assets():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        asset_type = request.form.get("asset_type", "").strip()
        importance = request.form.get("importance", "").strip()
        description = request.form.get("description", "").strip()

        if not name or not asset_type or not importance:
            flash("Please complete all required fields.", "error")
            return redirect(url_for("manage_assets"))

        connection = get_db_connection()

        connection.execute("""
            INSERT INTO assets (name, asset_type, description, importance)
            VALUES (?, ?, ?, ?)
        """, (name, asset_type, description, importance))

        connection.commit()
        connection.close()

        flash("Asset registered successfully!", "success")

        return redirect(url_for("manage_assets"))

    connection = get_db_connection()

    assets = connection.execute("""
        SELECT * FROM assets ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template("assets.html", assets=assets)


# ==========================================
# EDIT ASSET
# ==========================================

@app.route("/assets/edit/<int:asset_id>", methods=["GET", "POST"])
def edit_asset(asset_id):

    connection = get_db_connection()

    asset = connection.execute(
        "SELECT * FROM assets WHERE id = ?", (asset_id,)
    ).fetchone()

    if asset is None:
        connection.close()
        flash("Asset not found.", "error")
        return redirect(url_for("manage_assets"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        asset_type = request.form.get("asset_type", "").strip()
        importance = request.form.get("importance", "").strip()
        description = request.form.get("description", "").strip()

        if not name or not asset_type or not importance:
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for("edit_asset", asset_id=asset_id))

        connection.execute("""
            UPDATE assets
            SET name = ?, asset_type = ?, description = ?, importance = ?
            WHERE id = ?
        """, (name, asset_type, description, importance, asset_id))

        connection.commit()
        connection.close()

        flash("Asset updated successfully!", "success")

        return redirect(url_for("manage_assets"))

    connection.close()

    return render_template("edit_asset.html", asset=asset)


# ==========================================
# DELETE ASSET
# ==========================================

@app.route("/assets/delete/<int:asset_id>", methods=["POST"])
def delete_asset(asset_id):

    connection = get_db_connection()

    connection.execute(
        "DELETE FROM assets WHERE id = ?", (asset_id,)
    )

    connection.commit()
    connection.close()

    flash("Asset deleted successfully.", "success")

    return redirect(url_for("manage_assets"))


# ==========================================
# RUN APPLICATION
# ==========================================


# ==========================================
# RISK ASSESSMENT - REGISTER AND VIEW
# ==========================================

@app.route("/risk-assessment", methods=["GET", "POST"])
def manage_risk_assessments():

    connection = get_db_connection()

    # Retrieve registered assets, threats and vulnerabilities
    assets = connection.execute("""
        SELECT id, name FROM assets ORDER BY name ASC
    """).fetchall()

    threats = connection.execute("""
        SELECT id, asset_id, threat_name FROM threats
        ORDER BY threat_name ASC
    """).fetchall()

    vulnerabilities = connection.execute("""
        SELECT id, asset_id, vulnerability_name FROM vulnerabilities
        ORDER BY vulnerability_name ASC
    """).fetchall()

    if request.method == "POST":

        asset_id = request.form.get("asset_id", "").strip()
        threat_id = request.form.get("threat_id", "").strip()
        vulnerability_id = request.form.get(
            "vulnerability_id", ""
        ).strip()
        likelihood = request.form.get("likelihood", "").strip()
        impact = request.form.get("impact", "").strip()

        # Validate required fields
        if not all([
            asset_id,
            threat_id,
            vulnerability_id,
            likelihood,
            impact
        ]):
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for("manage_risk_assessments"))

        # Validate numeric inputs
        if not all(value.isdigit() for value in [
            asset_id, threat_id, vulnerability_id,
            likelihood, impact
        ]):
            connection.close()
            flash("Please enter valid assessment values.", "error")
            return redirect(url_for("manage_risk_assessments"))

        likelihood = int(likelihood)
        impact = int(impact)

        # Ensure likelihood and impact are between 1 and 5
        if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
            connection.close()
            flash("Likelihood and impact must be between 1 and 5.", "error")
            return redirect(url_for("manage_risk_assessments"))

        # Confirm that the selected threat belongs to the asset
        threat = connection.execute("""
            SELECT id FROM threats
            WHERE id = ? AND asset_id = ?
        """, (threat_id, asset_id)).fetchone()

        # Confirm that the selected vulnerability belongs to the asset
        vulnerability = connection.execute("""
            SELECT id FROM vulnerabilities
            WHERE id = ? AND asset_id = ?
        """, (vulnerability_id, asset_id)).fetchone()

        if threat is None or vulnerability is None:
            connection.close()
            flash(
                "The selected threat and vulnerability must belong to the selected asset.",
                "error"
            )
            return redirect(url_for("manage_risk_assessments"))

        # Calculate risk score
        risk_score = likelihood * impact

        # Determine risk level
        if risk_score <= 4:
            risk_level = "Low"
        elif risk_score <= 9:
            risk_level = "Medium"
        elif risk_score <= 16:
            risk_level = "High"
        else:
            risk_level = "Critical"

        # Save risk assessment
        connection.execute("""
            INSERT INTO risk_assessments (
                asset_id,
                threat_id,
                vulnerability_id,
                likelihood,
                impact,
                risk_score,
                risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            asset_id,
            threat_id,
            vulnerability_id,
            likelihood,
            impact,
            risk_score,
            risk_level
        ))

        connection.commit()
        connection.close()

        flash(
            f"Risk assessment completed! Risk Score: {risk_score} ({risk_level})",
            "success"
        )

        return redirect(url_for("manage_risk_assessments"))

    # Retrieve saved risk assessments
    assessments = connection.execute("""
        SELECT
            risk_assessments.*,
            assets.name AS asset_name,
            threats.threat_name,
            vulnerabilities.vulnerability_name
        FROM risk_assessments
        JOIN assets
            ON risk_assessments.asset_id = assets.id
        JOIN threats
            ON risk_assessments.threat_id = threats.id
        JOIN vulnerabilities
            ON risk_assessments.vulnerability_id = vulnerabilities.id
        ORDER BY risk_assessments.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "risk_assessment.html",
        assets=assets,
        threats=threats,
        vulnerabilities=vulnerabilities,
        assessments=assessments
    )



# ==========================================
# VULNERABILITY ASSESSMENT - REGISTER AND VIEW
# ==========================================

@app.route("/vulnerabilities", methods=["GET", "POST"])
def manage_vulnerabilities():

    connection = get_db_connection()

    assets = connection.execute("""
        SELECT id, name FROM assets ORDER BY name ASC
    """).fetchall()

    if request.method == "POST":

        asset_id = request.form.get("asset_id", "").strip()
        vulnerability_name = request.form.get(
            "vulnerability_name", ""
        ).strip()
        vulnerability_category = request.form.get(
            "vulnerability_category", ""
        ).strip()
        severity = request.form.get("severity", "").strip()
        description = request.form.get("description", "").strip()

        if not asset_id or not vulnerability_name or not vulnerability_category or not severity:
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for("manage_vulnerabilities"))

        if not asset_id.isdigit():
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for("manage_vulnerabilities"))

        asset = connection.execute(
            "SELECT id FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()

        if asset is None:
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for("manage_vulnerabilities"))

        connection.execute("""
            INSERT INTO vulnerabilities
            (asset_id, vulnerability_name, vulnerability_category,
             severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            asset_id,
            vulnerability_name,
            vulnerability_category,
            severity,
            description
        ))

        connection.commit()
        connection.close()

        flash("Vulnerability registered successfully!", "success")
        return redirect(url_for("manage_vulnerabilities"))

    vulnerabilities = connection.execute("""
        SELECT
            vulnerabilities.*,
            assets.name AS asset_name
        FROM vulnerabilities
        JOIN assets ON vulnerabilities.asset_id = assets.id
        ORDER BY vulnerabilities.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "vulnerabilities.html",
        vulnerabilities=vulnerabilities,
        assets=assets
    )


# ==========================================
# EDIT VULNERABILITY
# ==========================================

@app.route("/vulnerabilities/edit/<int:vulnerability_id>",
           methods=["GET", "POST"])
def edit_vulnerability(vulnerability_id):

    connection = get_db_connection()

    vulnerability = connection.execute("""
        SELECT * FROM vulnerabilities WHERE id = ?
    """, (vulnerability_id,)).fetchone()

    if vulnerability is None:
        connection.close()
        flash("Vulnerability not found.", "error")
        return redirect(url_for("manage_vulnerabilities"))

    assets = connection.execute("""
        SELECT id, name FROM assets ORDER BY name ASC
    """).fetchall()

    if request.method == "POST":

        asset_id = request.form.get("asset_id", "").strip()
        vulnerability_name = request.form.get(
            "vulnerability_name", ""
        ).strip()
        vulnerability_category = request.form.get(
            "vulnerability_category", ""
        ).strip()
        severity = request.form.get("severity", "").strip()
        description = request.form.get("description", "").strip()

        if not asset_id or not vulnerability_name or not vulnerability_category or not severity:
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for(
                "edit_vulnerability",
                vulnerability_id=vulnerability_id
            ))

        if not asset_id.isdigit():
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for(
                "edit_vulnerability",
                vulnerability_id=vulnerability_id
            ))

        asset = connection.execute(
            "SELECT id FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()

        if asset is None:
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for(
                "edit_vulnerability",
                vulnerability_id=vulnerability_id
            ))

        connection.execute("""
            UPDATE vulnerabilities
            SET asset_id = ?,
                vulnerability_name = ?,
                vulnerability_category = ?,
                severity = ?,
                description = ?
            WHERE id = ?
        """, (
            asset_id,
            vulnerability_name,
            vulnerability_category,
            severity,
            description,
            vulnerability_id
        ))

        connection.commit()
        connection.close()

        flash("Vulnerability updated successfully!", "success")
        return redirect(url_for("manage_vulnerabilities"))

    connection.close()

    return render_template(
        "edit_vulnerability.html",
        vulnerability=vulnerability,
        assets=assets
    )


# ==========================================
# DELETE VULNERABILITY
# ==========================================

@app.route("/vulnerabilities/delete/<int:vulnerability_id>",
           methods=["POST"])
def delete_vulnerability(vulnerability_id):

    connection = get_db_connection()

    connection.execute("""
        DELETE FROM vulnerabilities WHERE id = ?
    """, (vulnerability_id,))

    connection.commit()
    connection.close()

    flash("Vulnerability deleted successfully.", "success")

    return redirect(url_for("manage_vulnerabilities"))



# ==========================================
# THREAT IDENTIFICATION - REGISTER AND VIEW
# ==========================================

@app.route("/threats", methods=["GET", "POST"])
def manage_threats():

    connection = get_db_connection()

    # Get all registered assets for the selection dropdown
    assets = connection.execute("""
        SELECT id, name FROM assets ORDER BY name ASC
    """).fetchall()

    if request.method == "POST":

        asset_id = request.form.get("asset_id", "").strip()
        threat_name = request.form.get("threat_name", "").strip()
        threat_category = request.form.get("threat_category", "").strip()
        description = request.form.get("description", "").strip()

        if not asset_id or not threat_name or not threat_category:
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for("manage_threats"))

        # Check that the selected asset exists
        asset = connection.execute(
            "SELECT id FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()

        if asset is None:
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for("manage_threats"))

        connection.execute("""
            INSERT INTO threats
            (asset_id, threat_name, threat_category, description)
            VALUES (?, ?, ?, ?)
        """, (asset_id, threat_name, threat_category, description))

        connection.commit()
        connection.close()

        flash("Threat registered successfully!", "success")
        return redirect(url_for("manage_threats"))

    # Retrieve threats together with their associated asset names
    threats = connection.execute("""
        SELECT
            threats.*,
            assets.name AS asset_name
        FROM threats
        JOIN assets ON threats.asset_id = assets.id
        ORDER BY threats.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "threats.html",
        threats=threats,
        assets=assets
    )


# ==========================================
# EDIT THREAT
# ==========================================

@app.route("/threats/edit/<int:threat_id>", methods=["GET", "POST"])
def edit_threat(threat_id):

    connection = get_db_connection()

    threat = connection.execute("""
        SELECT * FROM threats WHERE id = ?
    """, (threat_id,)).fetchone()

    if threat is None:
        connection.close()
        flash("Threat not found.", "error")
        return redirect(url_for("manage_threats"))

    assets = connection.execute("""
        SELECT id, name FROM assets ORDER BY name ASC
    """).fetchall()

    if request.method == "POST":

        asset_id = request.form.get("asset_id", "").strip()
        threat_name = request.form.get("threat_name", "").strip()
        threat_category = request.form.get("threat_category", "").strip()
        description = request.form.get("description", "").strip()

        if not asset_id or not threat_name or not threat_category:
            connection.close()
            flash("Please complete all required fields.", "error")
            return redirect(url_for("edit_threat", threat_id=threat_id))

        asset = connection.execute(
            "SELECT id FROM assets WHERE id = ?", (asset_id,)
        ).fetchone()

        if asset is None:
            connection.close()
            flash("Please select a valid asset.", "error")
            return redirect(url_for("edit_threat", threat_id=threat_id))

        connection.execute("""
            UPDATE threats
            SET asset_id = ?,
                threat_name = ?,
                threat_category = ?,
                description = ?
            WHERE id = ?
        """, (
            asset_id,
            threat_name,
            threat_category,
            description,
            threat_id
        ))

        connection.commit()
        connection.close()

        flash("Threat updated successfully!", "success")
        return redirect(url_for("manage_threats"))

    connection.close()

    return render_template(
        "edit_threat.html",
        threat=threat,
        assets=assets
    )


# ==========================================
# DELETE THREAT
# ==========================================

@app.route("/threats/delete/<int:threat_id>", methods=["POST"])
def delete_threat(threat_id):

    connection = get_db_connection()

    connection.execute(
        "DELETE FROM threats WHERE id = ?",
        (threat_id,)
    )

    connection.commit()
    connection.close()

    flash("Threat deleted successfully.", "success")

    return redirect(url_for("manage_threats"))


# ==========================================
# RISK REGISTER - VIEW ALL ASSESSED RISKS
# ==========================================

@app.route("/risk-register")
def risk_register():
    risks = get_risk_register()
    return render_template("risk_register.html", risks=risks)




if __name__ == "__main__":
    app.run(debug=True)
