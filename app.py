from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import os
from functools import wraps
from datetime import datetime # Make sure this is imported

# --- Initialize Flask app and SQLAlchemy ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key-change-me-for-production!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads' 

db = SQLAlchemy(app)

# --- CONTEXT PROCESSOR TO MAKE YEAR AVAILABLE TO ALL TEMPLATES ---
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year} # Provides {{ current_year }} in templates

# --- Admin Accounts (DEMO ONLY - NOT FOR PRODUCTION) ---
ADMIN_USERS = {
    "admin": "admin123",
    "admin2": "securepass456",
    "testadmin": "testpass" 
}

# --- Model Definitions ---
class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.String(200)) 
    reporter_name = db.Column(db.String(150), nullable=False) 
    reporter_email = db.Column(db.String(150), nullable=False) 
    reporter_phone = db.Column(db.String(50), nullable=True)  
    timestamp = db.Column(db.DateTime, server_default=func.now())
    reporter_ip = db.Column(db.String(45), nullable=True) 

class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False) 
    email = db.Column(db.String(100), nullable=False)     
    message = db.Column(db.Text, nullable=False)          
    timestamp = db.Column(db.DateTime, server_default=func.now())

# --- Import Utilities ---
from forensic_utils import get_file_metadata, generate_incident_pdf_report, INVESTIGATIVE_FRAMEWORKS 
from flask import send_file

# --- Create upload folder ---
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

INCIDENT_CATEGORIES = [
    "Phishing", "Malware/Ransomware", "Data Breach", "Online Harassment/Cyberbullying",
    "Account Compromise", "Denial of Service (DoS)", "Identity Theft", "Financial Fraud", "Other"
]

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ... (Rest of your routes: index, submit_report, uploaded_file, view_report_detail, 
#      download_report_pdf, about, contact, login, logout, admin, api_admin_chart_data, 
#      delete_report, delete_contact_message - ALL REMAIN THE SAME as the last full app.py) ...
@app.route('/')
def index():
    return render_template('index.html', incident_categories=INCIDENT_CATEGORIES)

@app.route('/submit_report', methods=['POST'])
def submit_report():
    incident_type = request.form.get('incident_type')
    description = request.form.get('description')
    reporter_name = request.form.get('reporter_name') 
    reporter_email = request.form.get('reporter_email') 
    reporter_phone = request.form.get('reporter_phone') 
    evidence_file = request.files.get('evidence')

    if request.headers.getlist("X-Forwarded-For"):
       reporter_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
       reporter_ip = request.remote_addr

    if not all([incident_type, description, reporter_name, reporter_email]): # Phone is optional
        flash('Incident Type, Description, Your Name, and Your Email are required fields.', 'error')
        return render_template('index.html', 
                               incident_categories=INCIDENT_CATEGORIES,
                               s_incident_type=incident_type, 
                               s_description=description,
                               s_reporter_name=reporter_name,
                               s_reporter_email=reporter_email,
                               s_reporter_phone=reporter_phone)


    evidence_db_path = None
    if evidence_file and evidence_file.filename != '':
        filename = os.path.basename(evidence_file.filename)
        disk_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            evidence_file.save(disk_save_path)
            evidence_db_path = disk_save_path 
        except Exception as e:
            flash(f'Error saving evidence file: {e}', 'error')

    new_report = Report(
        incident_type=incident_type,
        description=description,
        evidence=evidence_db_path,
        reporter_name=reporter_name,     
        reporter_email=reporter_email,   
        reporter_phone=reporter_phone,   
        reporter_ip=reporter_ip 
    )
    db.session.add(new_report)
    db.session.commit()
    flash('Report submitted successfully! Thank you for your report.', 'success')
    return redirect(url_for('success'))

@app.route('/uploads/<path:filename>') 
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/report/<int:report_id>')
@login_required
def view_report_detail(report_id): 
    report = Report.query.get_or_404(report_id)
    forensic_data = None
    if report.evidence:
        evidence_full_disk_path = os.path.join(app.root_path, report.evidence)
        if os.path.exists(evidence_full_disk_path):
            forensic_data = get_file_metadata(evidence_full_disk_path)
        else:
            forensic_data = {"error": f"Evidence file '{report.evidence}' not found on server at '{evidence_full_disk_path}'."}
            
    incident_category = report.incident_type
    framework_steps = INVESTIGATIVE_FRAMEWORKS.get(incident_category, INVESTIGATIVE_FRAMEWORKS.get("Other", ["No specific framework defined for this category."]))
            
    return render_template('admin_report_detail.html', 
                           report=report, 
                           forensic_data=forensic_data,
                           framework_steps=framework_steps)

@app.route('/admin/report/<int:report_id>/download_pdf')
@login_required
def download_report_pdf(report_id):
    report = Report.query.get_or_404(report_id)
    forensic_data = None
    if report.evidence:
        evidence_full_disk_path = os.path.join(app.root_path, report.evidence)
        if os.path.exists(evidence_full_disk_path):
            forensic_data = get_file_metadata(evidence_full_disk_path)
    
    pdf_buffer = generate_incident_pdf_report(report, forensic_data) 
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f'incident_report_forensic_{report.id}.pdf',
        mimetype='application/pdf'
    )

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        message_text = request.form.get('message')
        if not all([full_name, email, message_text]):
            flash('All fields (Full Name, Email, Message) are required.', 'error')
            return render_template('contact.html', full_name=full_name, email=email, message=message_text)
        
        new_message = ContactMessage(full_name=full_name, email=email, message=message_text)
        db.session.add(new_message)
        db.session.commit()
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in ADMIN_USERS and ADMIN_USERS[username] == password:
            session['admin_logged_in'] = True
            session['admin_username'] = username 
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    reports_query = Report.query
    all_reports = reports_query.order_by(Report.timestamp.desc()).all()
    contact_messages = ContactMessage.query.order_by(ContactMessage.timestamp.desc()).all()

    total_reports = len(all_reports)
    first_report_date, last_report_date, avg_reports_per_day = None, None, 0.0
    if total_reports > 0:
        first_report_obj = reports_query.order_by(Report.timestamp.asc()).first()
        last_report_obj = all_reports[0]
        if first_report_obj and first_report_obj.timestamp: first_report_date = first_report_obj.timestamp
        if last_report_obj and last_report_obj.timestamp: last_report_date = last_report_obj.timestamp
        if first_report_date and last_report_date:
            days_span = max(1, (last_report_date - first_report_date).days + 1)
            avg_reports_per_day = total_reports / days_span
        elif total_reports == 1 and first_report_date: avg_reports_per_day = 1.0

    reports_with_evidence = reports_query.filter(Report.evidence != None, Report.evidence != '').count()
    reports_without_evidence = total_reports - reports_with_evidence
    
    report_type_analysis_table = db.session.query(Report.incident_type, func.count(Report.id).label('count')).group_by(Report.incident_type).order_by(func.count(Report.id).desc()).all()
    reports_per_month_table = db.session.query(func.strftime('%Y-%m', Report.timestamp).label('month_year'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('month_year').order_by('month_year').all()
    days_ordered = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'] 
    dow_map_num_to_name = {str(i): days_ordered[i] for i in range(7)} 
    reports_by_dow_query = db.session.query(func.strftime('%w', Report.timestamp).label('day_of_week_num'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('day_of_week_num').all()
    dow_counts = {day: 0 for day in days_ordered}
    for item in reports_by_dow_query:
        day_name = dow_map_num_to_name.get(str(item.day_of_week_num))
        if day_name: dow_counts[day_name] = item.count
    reports_by_day_of_week_table = [(day, dow_counts[day]) for day in days_ordered if dow_counts[day] > 0]
    reports_by_hour_query = db.session.query(func.strftime('%H', Report.timestamp).label('hour_of_day'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('hour_of_day').order_by('hour_of_day').all()
    hourly_counts = {f"{h:02d}": 0 for h in range(24)}
    for item in reports_by_hour_query:
        if item.hour_of_day is not None: hourly_counts[item.hour_of_day] = item.count
    reports_by_hour_table = [(f"{h:02d}:00", hourly_counts[f"{h:02d}"]) for h in range(24) if hourly_counts[f"{h:02d}"] > 0]

    return render_template('admin.html',
                           reports=all_reports,
                           contact_messages=contact_messages,
                           total_reports=total_reports,
                           first_report_date=first_report_date,
                           last_report_date=last_report_date,
                           avg_reports_per_day=avg_reports_per_day,
                           reports_with_evidence=reports_with_evidence,
                           reports_without_evidence=reports_without_evidence,
                           report_type_analysis_table=report_type_analysis_table,
                           reports_per_month_table=reports_per_month_table,
                           reports_by_day_of_week_table=reports_by_day_of_week_table,
                           reports_by_hour_table=reports_by_hour_table
                           )

@app.route('/api/admin/chart-data')
@login_required
def api_admin_chart_data():
    reports_query = Report.query
    total_reports_for_charts = reports_query.count() 
    report_type_analysis_query_chart = db.session.query( Report.incident_type, func.count(Report.id).label('count')).group_by(Report.incident_type).order_by(func.count(Report.id).desc()).all()
    chart_data_type = {"labels": [item.incident_type for item in report_type_analysis_query_chart], "data": [item.count for item in report_type_analysis_query_chart]}
    reports_per_month_query_chart = db.session.query( func.strftime('%Y-%m', Report.timestamp).label('month_year'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('month_year').order_by('month_year').all()
    chart_data_monthly = {"labels": [item.month_year for item in reports_per_month_query_chart], "data": [item.count for item in reports_per_month_query_chart]}
    days_ordered_api = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'] 
    dow_map_num_to_name_api = {str(i): days_ordered_api[i] for i in range(7)} 
    reports_by_dow_query_chart = db.session.query( func.strftime('%w', Report.timestamp).label('day_of_week_num'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('day_of_week_num').all()
    dow_counts_chart = {day: 0 for day in days_ordered_api} 
    for item in reports_by_dow_query_chart:
        day_name = dow_map_num_to_name_api.get(str(item.day_of_week_num)) 
        if day_name: dow_counts_chart[day_name] = item.count
    chart_data_dow = {"labels": days_ordered_api, "data": [dow_counts_chart[day] for day in days_ordered_api]}
    reports_by_hour_query_chart = db.session.query( func.strftime('%H', Report.timestamp).label('hour_of_day'), func.count(Report.id).label('count')).filter(Report.timestamp != None).group_by('hour_of_day').order_by('hour_of_day').all()
    hourly_counts_chart = {f"{h:02d}": 0 for h in range(24)}
    for item in reports_by_hour_query_chart:
        if item.hour_of_day is not None: hourly_counts_chart[item.hour_of_day] = item.count
    chart_data_hourly = {"labels": [f"{h:02d}:00" for h in range(24)], "data": [hourly_counts_chart[f"{h:02d}"] for h in range(24)]}
    return jsonify(total_reports=total_reports_for_charts, chart_type=chart_data_type, chart_monthly=chart_data_monthly, chart_dow=chart_data_dow, chart_hourly=chart_data_hourly)

@app.route('/success')
def success():
    return render_template('success.html')

# --- DELETE ROUTES ---
@app.route('/admin/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    report_to_delete = Report.query.get_or_404(report_id)
    if report_to_delete.evidence:
        evidence_full_disk_path = os.path.join(app.root_path, report_to_delete.evidence)
        if os.path.exists(evidence_full_disk_path):
            try:
                os.remove(evidence_full_disk_path)
                flash(f'Evidence file {os.path.basename(report_to_delete.evidence)} deleted.', 'info')
            except Exception as e: flash(f'Error deleting evidence file: {str(e)}', 'error')
    try:
        db.session.delete(report_to_delete)
        db.session.commit()
        flash(f'Report ID {report_id} has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting report ID {report_id}: {str(e)}', 'error')
    return redirect(url_for('admin'))

@app.route('/admin/delete_contact/<int:message_id>', methods=['POST'])
@login_required
def delete_contact_message(message_id):
    message_to_delete = ContactMessage.query.get_or_404(message_id)
    try:
        db.session.delete(message_to_delete)
        db.session.commit()
        flash(f'Contact message ID {message_id} has been successfully deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting contact message ID {message_id}: {str(e)}', 'error')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)