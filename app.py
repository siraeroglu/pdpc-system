from flask import Flask, render_template, Response, request, redirect, url_for, flash, session, send_file
app = Flask(__name__)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import cv2
import os
from io import BytesIO
from reportlab.pdfgen import canvas
from ultralytics import YOLO
import numpy as np
from werkzeug.utils import secure_filename
import time
model = YOLO("yolov8n.pt")  
from dotenv import load_dotenv
import os
load_dotenv()   # .env dosyası
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
import bcrypt
from datetime import datetime, timedelta
app.permanent_session_lifetime = timedelta(minutes=30)  #oturumun kalıcı olması
import cv2
IP_CAMERA_URL = "rtsp://cmpe:cmpe2025@172.20.53.66:554/live.sdp"


count_var = 0

app.secret_key = os.environ.get('SECRET_KEY')

# şifre yenileme/smtp ayarları
app.config.update(
    MAIL_SERVER        = os.environ['SMTP_SERVER'],
    MAIL_PORT          = int(os.environ['SMTP_PORT']),
    MAIL_USE_TLS       = True,
    MAIL_USE_SSL       = False,
    MAIL_USERNAME      = os.environ['SMTP_USERNAME'],
    MAIL_PASSWORD      = os.environ['SMTP_PASSWORD'],
    MAIL_DEFAULT_SENDER= os.environ['SMTP_USERNAME']
)


from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

###################################-------DATABASE-------############################################
POSTGRES_USER = "peoplecount"
POSTGRES_PASSWORD = "123456"
POSTGRES_DB = "mydb"
POSTGRES_HOST = "localhost" 

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:5432/{POSTGRES_DB}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#upload folder
UPLOAD_FOLDER = "static/uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#Flask-Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.now())
    is_admin = db.Column(db.Boolean, default=False)
    is_premium = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255), default="images/profile.png") 

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    media_type = db.Column(db.String(50), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, default=db.func.now())
    status = db.Column(db.String(50))
    user = db.relationship('User', backref='media')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    action = db.Column(db.String(150), nullable=False)
    time = db.Column(db.DateTime, default=db.func.now())
    user = db.relationship('User', backref='logs')

def log_action(user_id, action):
    new_log = Log(user_id=user_id, action=action)
    db.session.add(new_log)
    db.session.commit()

class PremiumRequest(db.Model):
    __tablename__ = 'premium_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(255), nullable=False)
    date_uploaded = db.Column(db.DateTime, default=db.func.now())
    user = db.relationship('User', backref='premium_requests')

from datetime import datetime

class Limit(db.Model):
    __tablename__ = 'limit'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    # kullanıcı premium mu değil mi kontrolü ayrı tutuluyor
    is_premium = db.Column(db.Boolean, default=False)
    # günlük limitler (sadece premium olmayanlar için dikkate alınacak)
    daily_limit_photo = db.Column(db.Integer, default=1)
    used_photo_count = db.Column(db.Integer, default=0)
    daily_limit_video = db.Column(db.Integer, default=1)
    used_video_count = db.Column(db.Integer, default=0)
    daily_limit_camera = db.Column(db.Integer, default=1)
    used_camera_count = db.Column(db.Integer, default=0)
    last_reset_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='limit')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# database kurulum
with app.app_context():
    db.create_all()


#################################----------USER-----------##########################################
#LOGIN/REGISTER
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        if "login" in request.form:
            username = request.form["username"]
            password = request.form["password"]
            user = User.query.filter_by(username=username).first()

            if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                session.permanent = True  #oturumun kalıcı olması
                login_user(user)
                log_action(user.id, "User logged in.") #LOG TABLOSU AKTİFLEŞTİRME

                # Kullanıcının Limit kaydı yoksa oluştur
                existing_limit = Limit.query.filter_by(user_id=user.id).first()
                if not existing_limit:
                    new_limit = Limit(
                        user_id=user.id,
                        is_premium=user.is_premium,
                        daily_limit_photo=1,
                        used_photo_count=0,
                        daily_limit_video=1,
                        used_video_count=0,
                        daily_limit_camera=1,
                        used_camera_count=0,
                        last_reset_date=datetime.utcnow()
                    )
                    db.session.add(new_limit)
                    db.session.commit()

                if user.is_admin:
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("user_home"))

            else:
                flash("Invalid username or password.", "danger")
                return redirect(url_for("home"))

        elif "register" in request.form:
            username = request.form["username"]
            password = request.form["password"]

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash("Email already exists. Please choose a different one.", "warning")
                return redirect(url_for("home"))

            if not username or not password:
                flash("Email and password are required.", "danger")
                return redirect(url_for("home"))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password=hashed_password.decode('utf-8'), is_admin=False)

            db.session.add(new_user)
            db.session.commit()

            #Yeni kullanıcı için limit kaydı
            new_limit = Limit(
                user_id=new_user.id,
                is_premium=False,
                daily_limit_photo=1,
                used_photo_count=0,
                daily_limit_video=1,
                used_video_count=0,
                daily_limit_camera=1,
                used_camera_count=0,
                last_reset_date=datetime.utcnow()
            )
            db.session.add(new_limit)
            db.session.commit()

            flash("Account created successfully. You can now log in.", "success")
            return redirect(url_for("home"))

    return render_template("login_register.html")


# User Home Page
@app.route("/user_home")
@login_required
def user_home():
    if current_user.is_admin:  # eğer admin ise bu sayfaya erişemez
        flash("Unauthorized access", "danger")
        return redirect(url_for("admin_dashboard"))
    return render_template("user_home.html")


import os

UPLOAD_FOLDER = "static/uploads"
user_id = 1  # varsayılan kullanıcı ID'si

        #KULLANICI İÇİN HISTORY
@app.route("/view_history")
@login_required
def view_history():
    if current_user.is_admin:  # Eğer admin ise bu sayfaya erişemez
        flash("Unauthorized access", "danger")
        return redirect(url_for("admin_dashboard"))

    # Şu anki kullanıcının yüklediği medyalar
    media_files = Media.query.filter_by(user_id=current_user.id).all()

    return render_template("user_history.html", media_files=media_files)


@app.route('/upload_invoice', methods=['POST'])
@login_required
def upload_invoice():
    if 'invoice' not in request.files:
        flash("No file part", "danger")
        return redirect(url_for('payment'))

    file = request.files['invoice']
    if file.filename == '':
        flash("No selected file", "danger")
        return redirect(url_for('payment'))

    if file:
       filename = secure_filename(file.filename)

# yükleme klasörü (burada \ yerine / kullanılacak)
       upload_folder = os.path.join('uploads', 'receipts')
       upload_path = os.path.join(app.static_folder, upload_folder)
       os.makedirs(upload_path, exist_ok=True)

       file_path = os.path.join(upload_folder, filename).replace("\\", "/")  # 🔁 DÜZENLEME
       file.save(os.path.join(app.static_folder, file_path))

# veritabanına sadece uploads/receipts kısmı kaydedilmeli
       premium_request = PremiumRequest(user_id=current_user.id, filename=file_path)
       db.session.add(premium_request)
       db.session.commit()


       flash("Invoice uploaded successfully. Waiting for admin approval.", "success")
       return redirect(url_for('payment'))

@app.route("/my_history")
@login_required
def my_history():
    # kullanıcının yüklediği tüm medya dosyaları
    media_files = Media.query.filter_by(user_id=current_user.id).all()

    return render_template("my_history.html", media_files=media_files)


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')
    user = User.query.filter_by(username=email).first()
    if not user:
        flash('No user found with this email address.', 'danger')
        return redirect(url_for('user_home'))

    # 1 saat geçerli token 
    token = serializer.dumps(email, salt='pw-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)

    # MAIL İÇERİĞİ RESET PASSWORD
    msg = Message(
        subject="Reset Password Request",
        recipients=[email]
    )
    msg.body = f"""Welcome {user.username},

Click the link below to reset your password:
{reset_url}

Ignore this email if you did not make this request."""
    mail.send(msg)

    flash('A password reset link has been sent to your email.', 'success')
    return redirect(url_for('user_home'))


@app.route("/premium")
@login_required
def premium():
    return render_template("premium.html") 


from datetime import datetime, timedelta

@app.route("/upload", methods=['POST'])
@login_required
def upload_video():
    user_limit = Limit.query.filter_by(user_id=current_user.id).first()

    # eğer kullanıcıya ait limit yoksa oluştur
    if not user_limit:
        user_limit = Limit(
            user_id=current_user.id,
            is_premium=current_user.is_premium,
            last_reset_date=datetime.utcnow()
        )
        db.session.add(user_limit)
        db.session.commit()

    # premium değilse 24 saat kontrolü ve sayaç sıfırlama
    if not current_user.is_premium:
        if datetime.utcnow() - user_limit.last_reset_date > timedelta(days=1):
            user_limit.used_photo_count = 0
            user_limit.used_video_count = 0
            user_limit.last_reset_date = datetime.utcnow()
            db.session.commit()

    # Dosya kontrolü
    if 'file' not in request.files:
        flash("File not found.", "danger")
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash("No file selected.", "danger")
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(file_path)

        media_type = "video" if filename.lower().endswith(('mp4', 'avi', 'mov')) else "photo"
    
        try:
            # Limit kontrolü (premium olmayanlar için)
            if not current_user.is_premium:
                if media_type == "photo" and user_limit.used_photo_count >= user_limit.daily_limit_photo:
                    flash("Trial users can upload only 1 photo per day.", "warning")
                    return redirect(url_for("user_home"))
                if media_type == "video" and user_limit.used_video_count >= user_limit.daily_limit_video:
                    flash("Trial users can upload only 1 video per day.", "warning")
                    return redirect(url_for("user_home"))

            # Medyayı kaydet
            new_media = Media(
                user_id=current_user.id,
                media_type=media_type,
                file_path=f"static/uploads/{filename}",
                status="processed"
            )
            db.session.add(new_media)
            print("Media added to session")

            # Sayaçları güncelle
            if not current_user.is_premium:
                if media_type == "photo":
                    user_limit.used_photo_count += 1
                elif media_type == "video":
                    user_limit.used_video_count += 1

                db.session.add(user_limit)  #sayaç commitlenmezse güncellenmez

            db.session.commit()
            print("DB COMMIT DONE")

            #Log kaydet
            log_action(current_user.id, f"{media_type.capitalize()} uploaded.")

            flash("File uploaded successfully.", "success")
            return redirect(url_for('view_media', file_path=new_media.file_path, media_type=new_media.media_type))

        except Exception as e:
            db.session.rollback()
            print("DB COMMIT FAILED:", str(e))
            flash("Database error: " + str(e), "danger")
            return redirect(url_for("user_home"))


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # tokendan e-postayı çıkar (1 saat geçerli)
        email = serializer.loads(token, salt='pw-reset-salt', max_age=3600)
    except Exception:
        flash('The link is invalid or has expired.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_pw = request.form.get('password')
        user = User.query.filter_by(username=email).first()
        hashed_password = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_password.decode('utf-8')
        db.session.commit()
        flash('Your password has been updated successfully.', 'success')
        return redirect(url_for('home'))

    # GET isteğinde reset formu 
    return render_template('reset_password.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.username = request.form.get('username')

        file = request.files.get('profile_pic')
        if file and file.filename != '':
            ext = os.path.splitext(file.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png']:
                filename = f"user_{current_user.id}{ext}"
                image_folder = os.path.join(os.getcwd(), 'static', 'images')
                os.makedirs(image_folder, exist_ok=True)

                print("Will be recorded:", os.path.join(image_folder, filename))
                print("File arrived:", file.filename)

                # önceki fotoğrafları sil
                for old_ext in ['.jpg', '.jpeg', '.png']:
                    old_file = os.path.join(image_folder, f"user_{current_user.id}{old_ext}")
                    if os.path.exists(old_file):
                        os.remove(old_file)

                file.save(os.path.join(image_folder, filename))
                flash("Profile photo uploaded successfully.", "success")
            else:
                flash("Only JPG, JPEG, and PNG files are allowed.", "danger")

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html')

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        # 1)form verilerini al
        card_holder = request.form['card_holder']
        
        amount      = request.form['amount'] 
        user_email  = current_user.username

        # 2)PDF bufferı oluştur
        pdf_buffer = BytesIO()
        p = canvas.Canvas(pdf_buffer, pagesize=(595, 842))  # A4

        # 3)PDF içeriğini yaz
        p.setFont("Helvetica-Bold", 18)
        p.drawString(200, 800, "PAYMENT DOCUMENT")

        p.setFont("Helvetica", 12)
        p.drawString(50, 760, f"USER EMAIL: {user_email}")
        p.drawString(50, 730, f"CARD OWNER NAME: {card_holder}")
        p.drawString(50, 650, f"AMOUNT PAID: {amount} TL")

        p.showPage()
        p.save()
        pdf_buffer.seek(0)

        # 4)PDFi indirme olarak gönder
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name="dekont.pdf",
            mimetype="application/pdf"
        )

    # GET:formu göster
    return render_template('payment.html')

#################################-------------ADMIN--------------#########################################
@app.route("/admin_dashboard", methods=["GET", "POST"])
@login_required
def admin_dashboard():
    if not current_user.is_admin:  # Kullanıcı admin değilse erişimi engelle
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))
    # Tüm kullanıcıları veritabanından çek
    users = User.query.filter_by(is_admin=False).all()
    return render_template("admin_dashboard.html", users=users)


@app.route("/update_user/<int:user_id>", methods=["POST"])
@login_required
def update_user(user_id):
    if not current_user.is_admin:  # Kullanıcı admin değilse erişimi engelle
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))
    # Kullanıcıyı bul
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    # Kullanıcı adını güncelle
    new_username = request.form["username"]
    user.username = new_username
    db.session.commit()
    flash("User updated successfully.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:  # Kullanıcı admin değilse erişimi engelle
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))
    # Kullanıcıyı bul ve sil
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    
    # Limit tablosundaki kayıtları sil
    limit_entry = Limit.query.filter_by(user_id=user.id).first()
    if limit_entry:
        db.session.delete(limit_entry)

    # Media tablosundaki kayıtları sil
    media_entries = Media.query.filter_by(user_id=user.id).all()
    for media in media_entries:
        db.session.delete(media)

    # Log tablosundaki kayıtları sil
    log_entries = Log.query.filter_by(user_id=user.id).all()
    for log in log_entries:
        db.session.delete(log)

    premium_entries = PremiumRequest.query.filter_by(user_id=user.id).all()
    for request_entry in premium_entries:
        db.session.delete(request_entry)


    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/make_premium/<int:user_id>", methods=["POST"])
@login_required
def make_premium(user_id):
    if not current_user.is_admin:  # Sadece adminler bu işlemi yapabilir
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))
    # Kullanıcıyı bul
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    # Kullanıcıyı premium yap
    user.is_premium = True
    db.session.commit()
    flash(f"{user.username} is now a premium user.", "success")
    return redirect(url_for("admin_dashboard"))


#admin için history
@app.route("/user_history/<int:user_id>")
@login_required
def user_history(user_id):
    if not current_user.is_admin:  # Sadece adminler bu sayfaya erişebilir
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))
    # Kullanıcıyı bul ve yüklediği medyaları al
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    media_files = Media.query.filter_by(user_id=user_id).all()
    return render_template("user_history.html", user=user, media_files=media_files)


@app.route("/view_receipt/<int:user_id>")
@login_required
def view_receipt(user_id):
    if not current_user.is_admin:
        flash("Unauthorized access", "danger")
        return redirect(url_for("index"))

    request_entry = PremiumRequest.query.filter_by(user_id=user_id).order_by(PremiumRequest.date_uploaded.desc()).first()
    if not request_entry:
        flash("No receipt found for this user.", "warning")
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for('static', filename=request_entry.filename))


#LOG OUT
@app.route("/logout")
@login_required
def logout():
    log_action(current_user.id, "User logged out.") #LOG TABLOSU AKTİFLEŞTİRME
    logout_user()
    return redirect(url_for("home"))


# Route for the main page
@app.route("/index")
@login_required
def index():
    return render_template('upload_page.html')


############################################# KAMERA-VİDEO-FOTOĞRAF #######################################################

@app.route("/view_media")
@login_required
def view_media():
    file_path = request.args.get("file_path")
    media_type = request.args.get("media_type")

    if not file_path or not media_type:
        flash("Invalid request.", "danger")
        return redirect(url_for("index"))

    if media_type == 'photo':
        return render_template("media_display.html", file_path=file_path, media_type=media_type)
    elif media_type == 'video':
        return render_template("video_stream.html", file_path=file_path)

#fotoğraf ya da videolardaki insanların tespiti için
def process_media(file_path):
    global count_var

    # eğer video dosyasıysa
    if file_path.lower().endswith(('mp4', 'avi', 'mov')):
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened():
            print(f"Could not open video file: {file_path}")
            return None

        skip_rate = 5  # Her 10. kareyi işle (hızlandırmak için)
        frame_index = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            frame_index += 1
            if frame_index % skip_rate != 0:
                continue  # bu kareyi atla

            frame = process_frame(frame, model)
            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()

            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        cap.release()

    # Resim dosyasıysa
    elif file_path.lower().endswith(('png', 'jpg', 'jpeg', 'gif', 'avif')):
        frame = cv2.imread(file_path)
        if frame is None:
            print(f"Could not open image file: {file_path}")
            return None

        frame = process_frame(frame, model)
        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    # Desteklenmeyen dosya türü
    else:
        print("Unsupported file format.")
        return None

        
def process_frame(frame, model):
    """tek bir kare üzerinde insanları tespit eder ve işleme uygular"""
    global count_var

    frame = cv2.resize(frame, (1280, 720))
    centr_pt_cur_fr = []
    results = model(frame)
    result = results[0]

    classes = np.array(result.boxes.cls.cpu(), dtype="int")
    bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")

    idx = [i for i, cls in enumerate(classes) if cls == 0]  # Class 0 -> İnsan
    bbox = [bboxes[i] for i in idx]

    for box in bbox:
        (x, y, x2, y2) = box
        cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)
        cx = int((x + x2) / 2)
        cy = int((y + y2) / 2)
        centr_pt_cur_fr.append((cx, cy))
        cv2.circle(frame, (cx, cy), 5, (255, 0, 0), -1)

    head_count = len(centr_pt_cur_fr)
    count_var = head_count

    cv2.putText(frame, f'People Count: {head_count}', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

    return frame

def generate_frames(file_path): # kişi sayımı
    global count_var
    model = YOLO("yolov8n.pt")
    
    # fotoğraf mı yoksa video mu kontrol ediyoruz
    if file_path.lower().endswith(('png', 'jpg', 'jpeg')):
        # Fotoğraf işleme
        frame = cv2.imread(file_path)
        results = model(frame)
        result = results[0]

        # insanları tespit eediyoruz
        classes = np.array(result.boxes.cls.cpu(), dtype="int")
        bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")

        idx = [i for i, cls in enumerate(classes) if cls == 0]
        bbox = [bboxes[i] for i in idx]

        for box in bbox:
            (x, y, x2, y2) = box
            cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)

        # insan sayısını ekle
        count_var = len(bbox)
        cv2.putText(frame, f'People Count: {count_var}', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        # fotoğraf için sadece bir kez yield yap
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    else:
        # video işleme için 
        cap = cv2.VideoCapture(file_path)

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            frame = cv2.resize(frame, (1280, 720))

            centr_pt_cur_fr = []
            results = model(frame)
            result = results[0]

            classes = np.array(result.boxes.cls.cpu(), dtype="int")
            bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")

            idx = [i for i, cls in enumerate(classes) if cls == 0]
            bbox = [bboxes[i] for i in idx]

            for box in bbox:
                (x, y, x2, y2) = box
                cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)
                cx = int((x + x2) / 2)
                cy = int((y + y2) / 2)
                centr_pt_cur_fr.append((cx, cy))
                cv2.circle(frame, (cx, cy), 5, (255, 0, 0), -1)

            head_count = len(centr_pt_cur_fr)
            count_var = head_count

            cv2.putText(frame, f'People Count: {head_count}', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        cap.release()

        
#bilgisayardan canlı görüntüyü alır ve insan tespiti yapar
def generate_camera_frames():
    global count_var
    model = YOLO("yolov8n.pt")

    # öncelikle index=1 (USB) yoksa index=0 (laptop)-webcam özelliği için
    cap = None
    for index in [1, 0]:
        test_cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
        if test_cap.isOpened():
            cap = test_cap
            print(f"Camera index used: {index}")
            break
    if cap is None:
        print("Camera cannot found.")
        return

  #pc kamerası hızlandırmak
    frame_skip = 1
    frame_count = 0

    while True:
        success, frame = cap.read()
        if not success:
            break

        frame = cv2.resize(frame, (1280, 720))
        frame_count += 1

        if frame_count % frame_skip != 0:
            continue # modeli her frame için çalıştırmayıp bazı kareleri atlıyoruz

        centr_pt_cur_fr = []
        results = model(frame)
        result = results[0]

        classes = np.array(result.boxes.cls.cpu(), dtype="int")
        bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")

        idx = [i for i, cls in enumerate(classes) if cls == 0]
        bbox = [bboxes[i] for i in idx]

        for box in bbox:
            x, y, x2, y2 = box
            cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)
            cx = int((x + x2) / 2)
            cy = int((y + y2) / 2)
            centr_pt_cur_fr.append((cx, cy))
            cv2.circle(frame, (cx, cy), 5, (255, 0, 0), -1)

        head_count = len(centr_pt_cur_fr)
        count_var = head_count

        cv2.putText(frame, f'People Count: {head_count}', (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    cap.release()

    
def generate_ip_camera_frames(rtsp_url):
    model = YOLO("yolov8n.pt")

    cap = cv2.VideoCapture(rtsp_url)
    if not cap.isOpened():
        print(f"Could not open IP camera: {rtsp_url}")
        return

    while True:
        success, frame = cap.read()
        if not success:
            break

        frame = cv2.resize(frame, (1280, 720))

        # YOLO işlemleri
        results = model(frame)
        result = results[0]

        classes = np.array(result.boxes.cls.cpu(), dtype="int")
        bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")

        idx = [i for i, cls in enumerate(classes) if cls == 0]
        bbox = [bboxes[i] for i in idx]

        for box in bbox:
            (x, y, x2, y2) = box
            cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)

        cv2.putText(frame, f'People Count: {len(bbox)}', (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

        _, buffer = cv2.imencode('.jpg', frame)
        frame_bytes = buffer.tobytes()

        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    cap.release()


@app.route("/ip_camera_feed")
@login_required
def ip_camera_feed():
    rtsp_url = session.get('ip_camera_url')
    if not rtsp_url:
        flash("No IP camera URL provided!", "danger")
        return redirect(url_for("user_home"))

    return Response(generate_ip_camera_frames(rtsp_url),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route("/start_ip_camera", methods=["POST"])
@login_required
def start_ip_camera():
    ip = request.form.get("ip")
    port = request.form.get("port")
    username = request.form.get("username")
    password = request.form.get("password")

    # RTSP URL template
    rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live.sdp"


    session['ip_camera_url'] = rtsp_url

   
    log_action(current_user.id, f"Started IP Camera: {rtsp_url}")

    return redirect(url_for("ip_camera_page"))

@app.route("/ip_camera_page")
@login_required
def ip_camera_page():
    return render_template("ip_camera_detection.html")


#kameradan gelen veri -----> tarayıcı 
@app.route("/camera_feed")
@login_required
def camera_feed():
    return Response(generate_camera_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


#kameranın açıldığı sayfaya yönlendirir
@app.route("/start_camera")
@login_required
def start_camera():
    user_limit = Limit.query.filter_by(user_id=current_user.id).first()

    if not current_user.is_premium:
        if not user_limit:
            flash("User limit not found.", "danger")
            return redirect(url_for("home"))

        # 24 saatlik süre doldu mu?
        if datetime.utcnow() - user_limit.last_reset_date > timedelta(days=1):
            user_limit.used_camera_count = 0
            user_limit.last_reset_date = datetime.utcnow()

        if user_limit.used_camera_count >= user_limit.daily_limit_camera:
            flash("Trial users can start the camera only once per day.", "warning")
            return redirect(url_for("user_home"))

        user_limit.used_camera_count += 1
        db.session.commit()
        log_action(current_user.id, "Camera started.")

    # mobile=1 geldiyse true
    auto_mobile = request.args.get("mobile") == "1"
    return render_template("camera_detection.html", auto_mobile=auto_mobile)


@app.route("/processed_image")
@login_required
def processed_image():
    file_path = request.args.get("file_path")

    full_path = os.path.join(app.root_path, file_path)

    if not os.path.exists(full_path):
        flash("File not found.", "danger")
        return redirect(url_for("index"))

    frame = cv2.imread(full_path)
    if frame is None:
        flash("Could not load image.", "danger")
        return redirect(url_for("index"))

    model = YOLO("yolov8n.pt")
    result = model(frame)[0]
    bboxes = np.array(result.boxes.xyxy.cpu(), dtype="int")
    classes = np.array(result.boxes.cls.cpu(), dtype="int")

    for i, cls in enumerate(classes):
        if cls == 0:  # Person class
            x, y, x2, y2 = bboxes[i]
            cv2.rectangle(frame, (x, y), (x2, y2), (0, 255, 0), 2)

    cv2.putText(frame, f'People Count: {(classes == 0).sum()}', (10, 30),
                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 4)

    _, buffer = cv2.imencode('.jpg', frame)
    return Response(buffer.tobytes(), mimetype='image/jpeg')


#yüklenen dosyayı işler ve gösterir
@app.route("/video_feed")
@login_required
def video_feed():
    file_path = request.args.get('file_path') 

    # tam dosya yolu
    full_file_path = os.path.join(app.root_path, file_path)

    if not os.path.exists(full_file_path): 
        flash("File not found.", "danger")
        return redirect(url_for("user_home"))

    
    return Response(process_media(full_file_path),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# count a döner
@app.route("/count")
@login_required
def count():
    return str(count_var)


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5432)  