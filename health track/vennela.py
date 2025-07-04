from flask import Flask, render_template, request, redirect, session, send_from_directory, make_response
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from io import BytesIO
from xhtml2pdf import pisa
import os
import email
app = Flask(__name__)  
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medtrack.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20))  # 'doctor' or 'patient'
class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    name = db.Column(db.String(100))
    dosage = db.Column(db.String(100))
    time = db.Column(db.String(100))
class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_username = db.Column(db.String(100))
    patient_username = db.Column(db.String(100))
    diagnosis_text = db.Column(db.Text)
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    doctor_username = db.Column(db.String(100))
    date = db.Column(db.String(20))
    time = db.Column(db.String(20))
    status = db.Column(db.String(20), default='Pending')  # 'Pending', 'Accepted', 'Rejected'
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    filename = db.Column(db.String(200))
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
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']           # New
        phone_no = request.form['phone_no']     # New

        # Save user into database
        conn = sqlite3.connect('medtrack.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, role, email, phone_no)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, role, email, phone_no))
        conn.commit()
        conn.close()

        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        user = User.query.filter_by(username=username, password=password, role=role).first()
        if user:
            session['username'] = username
            session['role'] = role
            if role == 'doctor':
                return redirect('/doctor_dashboard')
            else:
                return redirect('/patient_dashboard')
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    # Show all patients from User table who have role = 'patient'
    patients = User.query.filter_by(role='patient').all()
    return render_template('doctor_dashboard.html', username=session['username'], patients=patients)

@app.route('/add_diagnosis/<patient_username>', methods=['GET', 'POST'])
def add_diagnosis(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    if request.method == 'POST':
        diagnosis_text = request.form['diagnosis']
        new_diag = Diagnosis(
            doctor_username=session['username'],
            patient_username=patient_username,
            diagnosis_text=diagnosis_text
        )
        db.session.add(new_diag)
        db.session.commit()
        return redirect('/doctor_dashboard')

    return render_template('add_diagnosis.html', patient_username=patient_username)

@app.route('/view_patient_history/<patient_username>')
def view_patient_history(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    meds = Medicine.query.filter_by(patient_username=patient_username).all()
    diagnoses = Diagnosis.query.filter_by(patient_username=patient_username).all()
    return render_template('view_patient_history.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)
# Patient: Book Appointment
@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        patient_username = session['username']
        doctor_username = request.form['doctor_username']
        email = request.form['email']
        phone_no = request.form['phone_no']
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']

        conn = sqlite3.connect('medtrack.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO appointments (patient_username, doctor_username, email,phone_no, date, time, reason, status)
            VALUES (?, ?, ?, ?, ?, ?,? ,?)
        ''', (patient_username, doctor_username, email, phone_no, date, time, reason, 'Upcoming'))
        conn.commit()
        conn.close()

        return redirect('/patient_dashboard')

    conn = sqlite3.connect('medtrack.db',timeout=10)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE role='doctor'")
    doctors = cursor.fetchall()
    conn.close()
    return render_template('book_appointment.html', doctors=doctors)
@app.route('/doctor_appointments')
def doctor_appointments():
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')
    appointments = Appointment.query.filter_by(doctor_username=session['username']).all()
    return render_template('doctor_appointments.html', appointments=appointments)
@app.route('/update_appointment/<int:appointment_id>/<action>')
def update_appointment(appointment_id, action):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    appointment = Appointment.query.get_or_404(appointment_id)
    if action == 'accept':
        appointment.status = 'Accepted'
    elif action == 'reject':
        appointment.status = 'Rejected'
    db.session.commit()
    return redirect('/doctor_appointments')
@app.route('/patient_dashboard')
def patient_dashboard():
    if 'role' in session and session['role'] == 'patient':
        medicines = Medicine.query.filter_by(patient_username=session['username']).all()
        return render_template('patient_dashboard.html', username=session['username'], medicines=medicines)
    return redirect('/login')
@app.route('/add_medicine', methods=['GET', 'POST'])
def add_medicine():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        name = request.form['name']
        dosage = request.form['dosage']
        time = request.form['time']
        new_medicine = Medicine(
            patient_username=session['username'],
            name=name,
            dosage=dosage,
            time=time
        )
        db.session.add(new_medicine)
        db.session.commit()
        return redirect('/patient_dashboard')
    return render_template('add_medicine.html')

@app.route('/download_report/<patient_username>')
def download_report(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')
    meds = Medicine.query.filter_by(patient_username=patient_username).all()
    diagnoses = Diagnosis.query.filter_by(patient_username=patient_username).all()
    rendered_html = render_template('report_template.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(rendered_html.encode("UTF-8")), result)

    if not pdf.err:
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={patient_username}_report.pdf'
        return response
    else:
        return "Error generating PDF"
@app.route('/upload_report', methods=['GET', 'POST'])
def upload_report():
    if 'role' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        file = request.files['report']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Save in DB
            report = Report(patient_username=session['username'], filename=filename)
            db.session.add(report)
            db.session.commit()
            return redirect('/patient_dashboard')
        else:
            return "Invalid file type"
    return render_template('upload_report.html')
@app.route('/view_reports/<patient_username>')
def view_reports(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    reports = Report.query.filter_by(patient_username=patient_username).all()
    return render_template('view_reports.html', patient_username=patient_username, reports=reports)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route("/doctor_view_appointments")
def doctor_view_appointments():
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/login')

    doctor = session['username']
    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM appointments WHERE doctor_username=?", (doctor,))
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM appointments WHERE doctor_username=? AND status='Completed'", (doctor,))
    completed = cursor.fetchone()[0]

    cursor.execute("""
        SELECT a.patient_username, a.date, a.time, a.reason, u.email, u.phone_no
        FROM appointments a
        JOIN users u ON a.patient_username = u.username
        WHERE a.doctor_username=? AND a.status='Upcoming'
    """, (doctor,))
    
    appointments = cursor.fetchall()
    conn.close()

    return render_template("doctor_appointments_summary.html", total=total, completed=completed, appointments=appointments)
import smtplib
from email.message import EmailMessage



@app.route('/solve/<int:appointment_id>', methods=['GET', 'POST'])
def solve_appointment(appointment_id):
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/login')

    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        diagnosis = request.form['diagnosis']

        # Update appointment status to Completed and save diagnosis
        cursor.execute("UPDATE appointments SET status='Completed', diagnosis=? WHERE id=?", (diagnosis, appointment_id))

        # Get patient username from appointment
        cursor.execute("SELECT patient_username FROM appointments WHERE id=?", (appointment_id,))
        patient_username = cursor.fetchone()[0]

        # Get email and phone_no from users table
        cursor.execute("SELECT email, phone_no FROM users WHERE username=?", (patient_username,))
        result = cursor.fetchone()
        if result:
            email, phone_no = result

            # Compose and (optionally) send email
            message = f"""
            Hello {patient_username},

            Your appointment on {appointment_id} has been reviewed.
            Diagnosis: {diagnosis}

            Thank you,
            MedTrack Doctor
            """

            print("Email to send:")
            print(f"To: {email}")
            print(f"Message: {message}")
        conn.commit()
        conn.close()
        return redirect('/doctor_view_appointments')

    # GET method: show the form
    cursor.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,))
    appointment = cursor.fetchone()
    conn.close()
    return render_template('solve_appointment.html', appointment=appointment)        # Send email to patient
        
def send_email(to, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = "your_email@gmail.com"  # <-- Your Gmail
    msg['To'] = to

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login("your_email@gmail.com", "your_app_password")  # <-- Your app password
        smtp.send_message(msg)
        # 🔧 Add 'phone' column to users table if not already

def add_phone_column_once():
    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        print("✅ 'phone' column added to users table.")
    except sqlite3.OperationalError as e:
        print("ℹ️ Phone column might already exist or failed:", e)
    conn.commit()
    

# Call this function ONCE at app startup
add_phone_column_once()
conn = sqlite3.connect('medtrack.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM appointments")
rows = cursor.fetchall()
conn.close()

print("\n📋 Appointments Table Data:")
for row in rows:
    print(row)
conn.close()
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    ===============================================================
setup_db.py=====================
import sqlite3

conn = sqlite3.connect('medtrack.db')
cursor = conn.cursor()

# ✅ Updated users table with phone_no
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone_no TEXT,
        role TEXT NOT NULL
    )
''')
cursor.execute("DROP TABLE IF EXISTS appointments")

# Appointments table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT,
        patient_username TEXT NOT NULL,
        doctor_username TEXT NOT NULL,
        email TEXT,
        phone_no TEXT,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        reason TEXT,
        status TEXT
    )
''')

conn.commit()
# ✅ Print columns of appointments table
print("\n🔍 Columns in appointments table:")
cursor.execute("PRAGMA table_info(appointments)")
for col in cursor.fetchall():
    print(col)
conn.close()
print("✅ appointments table recreated with 'email' column.")

doctor_appointments_summary.html================================
<!DOCTYPE html>
<html>
<head>
    <title>Doctor Appointments Summary</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="container">
        <h2>Appointment Summary for Doctor</h2>

        <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; margin-top: 30px;">
            <div style="background-color: #004080; color: white; padding: 20px; border-radius: 10px; width: 200px; text-align: center;">
                <h3>{{ total }}</h3>
                <p>Total Appointments</p>
            </div>

            <div style="background-color: #006600; color: white; padding: 20px; border-radius: 10px; width: 200px; text-align: center;">
                <h3>{{ completed }}</h3>
                <p>Completed Appointments</p>
            </div>
            <h3 style="margin-top: 40px;">Upcoming Appointments</h3>
            <table border="1" style="margin-top: 20px; width: 100%; text-align: center;">
                <tr>
                    <th>Patient</th>
                    <th>email</th>
                    <th>Phone_no</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Reason</th>
                    <th>Action</th>
                </tr>
                {% for appt in appointments %}
                <tr>
                    <td>{{ appt[0] }}</td>
                    <td>{{ appt[1] }}</td>
                    <td>{{ appt[2] }}</td>
                    <td>{{ appt[3] }}</td>
                    <td>{{ appt[4] }}</td>
                    <td>{{ appt[5] }}</td>
                    <td><a href="/solve_appointment/{{ appt[6] }}" class="button">View & Solve</a></td>
                </tr>
                {% endfor %}
            </table>
        </div>

        <br><br>
        <a href="/doctor_dashboard" class="button">Back to Dashboard</a>
    </div>
</body>
</html>
============================================solve_appointment.html
<!DOCTYPE html>
<html>
<head>
    <title>Diagnosis for {{ patient }}</title>
</head>
<body>
    <div style="padding: 30px;">
        <h2>Appointment Details</h2>
        <p><strong>Patient:</strong> {{ patient }}</p>
        <p><strong>Date:</strong> {{ date }}</p>
        <p><strong>Time:</strong> {{ time }}</p>
        <p><strong>Reason:</strong> {{ reason }}</p>

        <form method="POST">
            <label for="solution">Diagnosis / Solution:</label><br>
            <textarea name="solution" rows="6" cols="50" required></textarea><br><br>
            <button type="submit">Submit Diagnosis</button>
        </form>
    </div>
</body>
</html>
=====================================changes app.py=================================================================
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import boto3
import uuid
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
users=[]
IS_DEV = True  # Change to False when AWS credentials are provided in lab

if not IS_DEV:
    import boto3
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('Appointments')
    sns = boto3.client('sns', region_name='us-east-1')
else:
    print("Running in development mode. AWS services are disabled.")


# AWS Configuration
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # e.g., 'us-east-1'
table = dynamodb.Table('Appointments')

# AWS SNS (will be configured next)
sns = boto3.client('sns', region_name='us-east-1')
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')
from werkzeug.security import generate_password_hash

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']
        phone_no = request.form['phone_no']

        users_table = dynamodb.Table('users')  # Connect to DynamoDB users table

        try:
            # ✅ Check if user already exists
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                return render_template('signup.html', error="Email already registered. Please use a different one.")

            # ✅ Optional: Hash the password
            hashed_password = generate_password_hash(password)

            # ✅ Save user to DynamoDB
            users_table.put_item(
                Item={
                    'email': email,
                    'name': username,
                    'password': hashed_password,
                    'role': role,
                    'phone_no': phone_no
                }
            )

            return redirect('/login')

        except Exception as e:
            return render_template('signup.html', error="Signup failed: " + str(e))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return render_template('login.html', error='Please enter email and password')

        try:
            users_table = dynamodb.Table('users')  # Connect to DynamoDB users table
            response = users_table.get_item(Key={'email': email})
            user = response.get('Item')

            if user and password == user['password']:  # For plain-text passwords
                # If using hashed passwords, replace the above with:
                # if user and check_password_hash(user['password'], password):

                session['user_email'] = email
                session['username'] = user.get('name', '')
                session['role'] = user.get('role')

                print(session)

                if session['role'] == 'patient':
                    return redirect(url_for('patient_dashboard'))
                elif session['role'] == 'doctor':
                    session['specialization'] = user.get('specialization', '')
                    return redirect(url_for('doctor_dashboard'))
                else:
                    return render_template('login.html', error='Invalid role')
            else:
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            return render_template('login.html', error=f"Login failed: {str(e)}")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/book_appointment', methods=['GET', 'POST'])
def appointment():
    if request.method == 'POST':
        # Extract form data
        name = request.form['name']
        email = request.form['email']
        date = request.form['date']
        time = request.form['time']
        age = request.form['age']
        gender = request.form['gender']
        problem = request.form['problem']
        specialization = request.form['specialization']
        filename = None

        # Handle file upload
        file = request.files.get('report')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join("static/uploads", filename))

        appointment_id = str(uuid.uuid4())

        # Save to DynamoDB
        table.put_item(
            Item={
                'appointment_id': appointment_id,
                'name': name,
                'email': email,
                'date': date,
                'time': time,
                'age': age,
                'gender': gender,
                'problem': problem,
                'specialization': specialization,
                'filename': filename,
                'status': 'Pending'
            }
        )

        # ✅ SNS Email to patient
    try:
        sns.publish(
        TopicArn='arn:aws:sns:us-east-1:your-account-id:medtrack',
        Message=f"Dear {name},\n\nYour appointment has been booked for {date} at {time}. We'll notify you once it's confirmed.\n\n- MedTrack Team",
        Subject="MedTrack Appointment Booking Confirmation"
    )
    except Exception as e:
      print("SNS publish failed:", str(e))

    flash('Appointment booked successfully!', 'success')
    return redirect(url_for('patient_dashboard'))

    return render_template("book_appointment.html")



@app.route("/patient-dashboard")
def patient_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    email = session['user_email']

    if not IS_DEV:
        try:
            response = table.scan()
            items = response.get('Items', [])
            appointments = [item for item in items if item.get('email') == email]
        except Exception as e:
            flash("Error loading appointments: " + str(e), "danger")
            appointments = []
    else:
        appointments = [
            {
                'name': 'Test User',
                'email': email,
                'date': '2025-07-03',
                'time': '10:00',
                'status': 'Pending',
                'specialization': 'Cardiology'
            }
        ]

    return render_template("patient_dashboard.html", name=session.get('username'), appointments=appointments)


@app.route("/doctor-dashboard")
def doctor_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    specialization = session.get('specialization', '')

    if not IS_DEV:
        try:
            response = table.scan()
            items = response.get('Items', [])
            appointments = [item for item in items if item.get('specialization') == specialization]
        except Exception as e:
            flash("Error loading appointments: " + str(e), "danger")
            appointments = []
    else:
        appointments = [
            {
                'name': 'Test Patient',
                'email': 'test@example.com',
                'date': '2025-07-04',
                'time': '12:00',
                'status': 'Pending',
                'specialization': specialization
            }
        ]

    return render_template("doctor_dashboard.html", name=session.get('username'), appointments=appointments)


@app.route('/solve/<appointment_id>')
def solve_appointment(appointment_id):
    response = table.get_item(Key={'appointment_id': appointment_id})
    appointment = response.get('Item')
    if not appointment:
        flash("Appointment not found", "error")
        return redirect(url_for('doctor_dashboard'))

    return render_template('solve.html', **appointment)


@app.route('/submit_diagnosis/<appointment_id>', methods=['POST'])
def submit_diagnosis(appointment_id):
    diagnosis = request.form.get('diagnosis')

    # 1️⃣ Update appointment in DynamoDB with diagnosis
    table.update_item(
        Key={'appointment_id': appointment_id},
        UpdateExpression="set #s = :status, diagnosis = :diagnosis",
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={
            ':status': 'Confirmed',
            ':diagnosis': diagnosis
        }
    )

    # 2️⃣ ✅ Send SNS email to patient
    appointment = table.get_item(Key={'appointment_id': appointment_id}).get('Item')
    if appointment:
        try:
            sns.publish(
                TopicArn='arn:aws:sns:your-region:your-account-id:your-topic-name',
                Message=f"Dear {appointment['name']},\n\nYour diagnosis has been confirmed. Please check your MedTrack dashboard for details.\n\n- MedTrack Team",
                Subject="MedTrack Diagnosis Confirmation"
            )
        except Exception as e:
            print("SNS publish failed:", str(e))

    # 3️⃣ Redirect with success message
    flash("Diagnosis submitted successfully", "success")
    return redirect(url_for('doctor_dashboard'))
if __name__ == '__main__':
     app.run(debug=True)
     ==============================final app.py========================================
from flask import Flask, render_template, request, redirect,url_for, session, send_from_directory, make_response
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from io import BytesIO
from xhtml2pdf import pisa
import os
import email
app = Flask(__name__)  
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medtrack.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20))  # 'doctor' or 'patient'
class Medicine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    name = db.Column(db.String(100))
    dosage = db.Column(db.String(100))
    time = db.Column(db.String(100))
class Diagnosis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_username = db.Column(db.String(100))
    patient_username = db.Column(db.String(100))
    diagnosis_text = db.Column(db.Text)
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    doctor_username = db.Column(db.String(100))
    date = db.Column(db.String(20))
    time = db.Column(db.String(20))
    status = db.Column(db.String(20), default='Pending')  # 'Pending', 'Accepted', 'Rejected'
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_username = db.Column(db.String(100))
    filename = db.Column(db.String(200))
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
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        email = request.form['email']           # New
        phone_no = request.form['phone_no']     # New

        # Save user into database
        conn = sqlite3.connect('medtrack.db')
        cursor = conn.cursor()
        # ✅ Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template('signup.html', error="Email already registered. Please use a different one.")

        cursor.execute('''
            INSERT INTO users (username, password, role, email, phone_no)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, role, email, phone_no))
        conn.commit()
        conn.close()

        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return render_template('login.html', error='Please enter email and password')

        conn = sqlite3.connect('medtrack.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_email'] = email
            session['username'] = user[1]  # ✅ Save username for later use
            session['role'] = user[5] 
            print(session)
            if user[5] == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user[5] == 'doctor':
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

    # Show all patients from User table who have role = 'patient'
    patients = User.query.filter_by(role='patient').all()
    return render_template('doctor_dashboard.html', username=session['username'], patients=patients)

@app.route('/add_diagnosis/<patient_username>', methods=['GET', 'POST'])
def add_diagnosis(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    if request.method == 'POST':
        diagnosis_text = request.form['diagnosis']
        new_diag = Diagnosis(
            doctor_username=session['username'],
            patient_username=patient_username,
            diagnosis_text=diagnosis_text
        )
        db.session.add(new_diag)
        db.session.commit()
        return redirect('/doctor_dashboard')

    return render_template('add_diagnosis.html', patient_username=patient_username)

@app.route('/view_patient_history/<patient_username>')
def view_patient_history(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    meds = Medicine.query.filter_by(patient_username=patient_username).all()
    diagnoses = Diagnosis.query.filter_by(patient_username=patient_username).all()
    return render_template('view_patient_history.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)
# Patient: Book Appointment
@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        patient_username = session['username']
        doctor_username = request.form['doctor_username']
        email = request.form['email']
        phone_no = request.form['phone_no']
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']

        conn = sqlite3.connect('medtrack.db')
        cursor = conn.cursor()
        cursor.execute('''
    INSERT INTO appointments (patient_username, doctor_username, email, phone_no, date, time, reason, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
''', (session['username'], doctor_username, email, phone_no, date, time, reason, 'Upcoming'))

        conn.commit()
        conn.close()

        return redirect('/patient_dashboard')

    conn = sqlite3.connect('medtrack.db',timeout=10)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE role='doctor'")
    doctors = cursor.fetchall()
    conn.close()
    return render_template('book_appointment.html', doctors=doctors)
@app.route('/doctor_appointments')
def doctor_appointments():
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    print("🔐 Logged-in doctor:", session['username'])  # ✅ Debug

    # Get doctor appointments
    appointments = Appointment.query.filter_by(doctor_username=session['username']).all()

    print("📋 Appointments fetched:", appointments)  # ✅ Debug

    return render_template('doctor_appointments.html', appointments=appointments)

@app.route('/update_appointment/<int:appointment_id>/<action>')
def update_appointment(appointment_id, action):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    appointment = Appointment.query.get_or_404(appointment_id)
    if action == 'accept':
        appointment.status = 'Accepted'
    elif action == 'reject':
        appointment.status = 'Rejected'
    db.session.commit()
    return redirect('/doctor_appointments')
@app.route('/patient_dashboard')
def patient_dashboard():
    if 'role' in session and session['role'] == 'patient':
        medicines = Medicine.query.filter_by(patient_username=session['username']).all()
        return render_template('patient_dashboard.html', username=session['username'], medicines=medicines)
    return redirect('/login')
@app.route('/add_medicine', methods=['GET', 'POST'])
def add_medicine():
    if 'username' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        name = request.form['name']
        dosage = request.form['dosage']
        time = request.form['time']
        new_medicine = Medicine(
            patient_username=session['username'],
            name=name,
            dosage=dosage,
            time=time
        )
        db.session.add(new_medicine)
        db.session.commit()
        return redirect('/patient_dashboard')
    return render_template('add_medicine.html')

@app.route('/download_report/<patient_username>')
def download_report(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')
    meds = Medicine.query.filter_by(patient_username=patient_username).all()
    diagnoses = Diagnosis.query.filter_by(patient_username=patient_username).all()
    rendered_html = render_template('report_template.html', patient_username=patient_username, meds=meds, diagnoses=diagnoses)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(rendered_html.encode("UTF-8")), result)

    if not pdf.err:
        response = make_response(result.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={patient_username}_report.pdf'
        return response
    else:
        return "Error generating PDF"
@app.route('/upload_report', methods=['GET', 'POST'])
def upload_report():
    if 'role' not in session or session['role'] != 'patient':
        return redirect('/login')

    if request.method == 'POST':
        file = request.files['report']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Save in DB
            report = Report(patient_username=session['username'], filename=filename)
            db.session.add(report)
            db.session.commit()
            return redirect('/patient_dashboard')
        else:
            return "Invalid file type"
    return render_template('upload_report.html')
@app.route('/view_reports/<patient_username>')
def view_reports(patient_username):
    if 'role' not in session or session['role'] != 'doctor':
        return redirect('/login')

    reports = Report.query.filter_by(patient_username=patient_username).all()
    return render_template('view_reports.html', patient_username=patient_username, reports=reports)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route("/doctor_view_appointments")
def doctor_view_appointments():
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/login')

    doctor = session['username']
    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM appointments WHERE doctor_username=?", (doctor,))
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM appointments WHERE doctor_username=? AND status='Completed'", (doctor,))
    completed = cursor.fetchone()[0]

    cursor.execute("""
    SELECT a.patient_username, u.email, u.phone_no, a.date, a.time, a.reason, a.id
    FROM appointments a
    JOIN users u ON a.patient_username = u.username
    WHERE a.doctor_username=? AND a.status='Upcoming'
""", (doctor,))

    
    appointments = cursor.fetchall()
    conn.close()

    return render_template("doctor_appointments_summary.html", total=total, completed=completed, appointments=appointments)
import smtplib
from email.message import EmailMessage



@app.route('/solve/<int:appointment_id>', methods=['GET', 'POST'])
def solve_appointment(appointment_id):
    if 'username' not in session or session['role'] != 'doctor':
        return redirect('/login')

    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        diagnosis = request.form['diagnosis']

        # Update appointment status to Completed and save diagnosis
        cursor.execute("UPDATE appointments SET status='Completed', diagnosis=? WHERE id=?", (diagnosis, appointment_id))

        # Get patient username from appointment
        cursor.execute("SELECT patient_username FROM appointments WHERE id=?", (appointment_id,))
        patient_username = cursor.fetchone()[0]

        # Get email and phone_no from users table
        cursor.execute("SELECT email, phone_no FROM users WHERE username=?", (patient_username,))
        result = cursor.fetchone()
        if result:
            email, phone_no = result

            # Compose and (optionally) send email
            message = f"""
            Hello {patient_username},

            Your appointment on {appointment_id} has been reviewed.
            Diagnosis: {diagnosis}

            Thank you,
            MedTrack Doctor
            """

            print("Email to send:")
            print(f"To: {email}")
            print(f"Message: {message}")
        conn.commit()
        conn.close()
        return redirect('/doctor_view_appointments')

    # GET method: show the form
    cursor.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,))
    appointment = cursor.fetchone()
    conn.close()
    return render_template('solve_appointment.html', appointment=appointment)        # Send email to patient
        
def send_email(to, subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = "your_email@gmail.com"  # <-- Your Gmail
    msg['To'] = to

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login("your_email@gmail.com", "your_app_password")  # <-- Your app password
        smtp.send_message(msg)
        # 🔧 Add 'phone' column to users table if not already

def add_phone_column_once():
    conn = sqlite3.connect('medtrack.db')
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        print("✅ 'phone' column added to users table.")
    except sqlite3.OperationalError as e:
        print("ℹ️ Phone column might already exist or failed:", e)
    conn.commit()
    

# Call this function ONCE at app startup
add_phone_column_once()
conn = sqlite3.connect('medtrack.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM appointments")
rows = cursor.fetchall()
conn.close()

print("\n📋 Appointments Table Data:")
for row in rows:
    print(row)
conn.close()
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
