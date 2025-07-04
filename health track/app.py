from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, make_response
from werkzeug.utils import secure_filename
from io import BytesIO
from xhtml2pdf import pisa
import boto3
import os
import uuid
from email.message import EmailMessage

# AWS Configuration
AWS_REGION_NAME = "us-east-1"
AWS_ACCESS_KEY_ID = "<your-access-key-id>"
AWS_SECRET_ACCESS_KEY = "<your-secret-access-key>"
SNS_TOPIC_ARN = "<your-sns-topic-arn>"

# AWS Resources
session_boto3 = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION_NAME
)
dynamodb = session_boto3.resource('dynamodb')
sns = session_boto3.client('sns')

users_table = dynamodb.Table('Users')
appointments_table = dynamodb.Table('Appointments')
diagnoses_table = dynamodb.Table('Diagnoses')
medicines_table = dynamodb.Table('Medicines')
reports_table = dynamodb.Table('Reports')

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/contactus')
def contactus():
    return render_template('contactus.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = {
            "username": request.form['username'],
            "password": request.form['password'],
            "role": request.form['role'],
            "email": request.form['email'],
            "phone_no": request.form['phone_no']
        }
        response = users_table.get_item(Key={"email": user['email']})
        if 'Item' in response:
            return render_template('signup.html', error="Email already registered.")
        users_table.put_item(Item=user)
        return redirect('/login')
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        response = users_table.get_item(Key={"email": email})
        user = response.get('Item')
        if user and user['password'] == password:
            session['user_email'] = email
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')
    all_users = users_table.scan().get('Items', [])
    patients = [u for u in all_users if u.get('role') == 'patient']
    return render_template('doctor_dashboard.html', username=session['username'], patients=patients)


@app.route('/add_diagnosis/<patient_username>', methods=['GET', 'POST'])
def add_diagnosis(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')
    if request.method == 'POST':
        diagnoses_table.put_item(Item={
            "id": str(uuid.uuid4()),
            "doctor_username": session['username'],
            "patient_username": patient_username,
            "diagnosis_text": request.form['diagnosis']
        })
        return redirect('/doctor_dashboard')
    return render_template('add_diagnosis.html', patient_username=patient_username)


@app.route('/view_patient_history/<patient_username>')
def view_patient_history(patient_username):
    all_meds = medicines_table.scan().get('Items', [])
    all_diags = diagnoses_table.scan().get('Items', [])
    meds = [m for m in all_meds if m['patient_username'] == patient_username]
    diagnoses = [d for d in all_diags if d['patient_username'] == patient_username]
    return render_template('view_patient_history.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)


@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/login')
    if request.method == 'POST':
        appointment = {
            "id": str(uuid.uuid4()),
            "patient_username": session['username'],
            "doctor_username": request.form['doctor_username'],
            "email": request.form['email'],
            "phone_no": request.form['phone_no'],
            "date": request.form['date'],
            "time": request.form['time'],
            "reason": request.form['reason'],
            "status": "Upcoming"
        }
        appointments_table.put_item(Item=appointment)
        return redirect('/patient_dashboard')
    doctors = [u['username'] for u in users_table.scan().get('Items', []) if u.get('role') == 'doctor']
    return render_template('book_appointment.html', doctors=doctors)


@app.route('/doctor_appointments')
def doctor_appointments():
    appointments = [a for a in appointments_table.scan().get('Items', []) if a['doctor_username'] == session['username']]
    return render_template('doctor_appointments.html', appointments=appointments)


@app.route('/patient_dashboard')
def patient_dashboard():
    if session.get('role') != 'patient':
        return redirect('/login')
    meds = [m for m in medicines_table.scan().get('Items', []) if m['patient_username'] == session['username']]
    return render_template('patient_dashboard.html', username=session['username'], medicines=meds)


@app.route('/add_medicine', methods=['GET', 'POST'])
def add_medicine():
    if session.get('role') != 'patient':
        return redirect('/login')
    if request.method == 'POST':
        medicines_table.put_item(Item={
            "id": str(uuid.uuid4()),
            "patient_username": session['username'],
            "name": request.form['name'],
            "dosage": request.form['dosage'],
            "time": request.form['time']
        })
        return redirect('/patient_dashboard')
    return render_template('add_medicine.html')


@app.route('/download_report/<patient_username>')
def download_report(patient_username):
    meds = [m for m in medicines_table.scan().get('Items', []) if m['patient_username'] == patient_username]
    diagnoses = [d for d in diagnoses_table.scan().get('Items', []) if d['patient_username'] == patient_username]
    rendered_html = render_template('report_template.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(rendered_html.encode("UTF-8")), result)
    if not pdf.err:
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={patient_username}_report.pdf'
        return response
    return "Error generating PDF"


@app.route('/upload_report', methods=['GET', 'POST'])
def upload_report():
    if session.get('role') != 'patient':
        return redirect('/login')
    if request.method == 'POST':
        file = request.files['report']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            reports_table.put_item(Item={"id": str(uuid.uuid4()), "patient_username": session['username'], "filename": filename})
            return redirect('/patient_dashboard')
    return render_template('upload_report.html')


@app.route('/view_reports/<patient_username>')
def view_reports(patient_username):
    reports = [r for r in reports_table.scan().get('Items', []) if r['patient_username'] == patient_username]
    return render_template('view_reports.html', patient_username=patient_username, reports=reports)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/solve/<string:appointment_id>', methods=['GET', 'POST'])
def solve_appointment(appointment_id):
    appointments = appointments_table.scan().get('Items', [])
    appointment = next((a for a in appointments if a['id'] == appointment_id), None)
    if request.method == 'POST':
        diagnosis = request.form['diagnosis']
        if appointment:
            appointment['status'] = 'Completed'
            appointment['diagnosis'] = diagnosis
            appointments_table.put_item(Item=appointment)
            patient = users_table.get_item(Key={"username": appointment['patient_username']}).get('Item')
            if patient:
                message = f"Hello {patient['username']},\n\nYour appointment has been reviewed.\nDiagnosis: {diagnosis}\n\n- MedTrack"
                sns.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject="Appointment Diagnosis")
        return redirect('/doctor_view_appointments')
    return render_template('solve_appointment.html', appointment=appointment)


if __name__ == '__main__':
    app.run(debug=True)

