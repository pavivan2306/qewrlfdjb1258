from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Ключ для безпеки сесій
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Підключення до SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Генеруємо майстер-ключ (зберігається тільки на сервері)
if not os.path.exists("master_key.key"):
    with open("master_key.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

# Завантажуємо майстер-ключ
with open("master_key.key", "rb") as key_file:
    MASTER_KEY = key_file.read()

fernet = Fernet(MASTER_KEY)


db = SQLAlchemy(app)  # Ініціалізація бази даних

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = "static/profile_pictures"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_aes_key():
    return os.urandom(32)  # 256-бітний AES-ключ

def encrypt_aes_key(aes_key):
    return fernet.encrypt(aes_key)  # Шифруємо ключ перед збереженням

def decrypt_aes_key(encrypted_key):
    return fernet.decrypt(encrypted_key)  # Дешифруємо перед використанням

# Модель користувачів
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)  # Додаємо поле для фото профілю
    aes_key_encrypted = db.Column(db.String(256), nullable=True)  # Зашифрований AES-ключ

class RegistrationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Унікальний ID заявки
    full_name = db.Column(db.String(150), nullable=False)  # ПІБ користувача
    username = db.Column(db.String(150), unique=True, nullable=False)  # Логін користувача
    password_hash = db.Column(db.String(256), nullable=False)  # Хеш пароля
    approved = db.Column(db.Boolean, default=False)  # Чи підтверджений акаунт адміністратором?

# Завантаження користувача для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Головна сторінка
@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))  # Якщо користувач не авторизований – відправляємо на сторінку входу

    if current_user.username == "admin":
        return render_template("admin_home.html")  # Адмін бачить панель адміністрування
    else:
        return render_template("user_home.html")  # Звичайний користувач бачить свою інформацію

# Сторінка входу
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash("Неправильний логін або пароль", "danger")
    return render_template("login.html")

# Вихід із системи
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# Обробка реєстрації
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Перевіряємо, чи паролі співпадають
        if password != confirm_password:
            flash("Паролі не співпадають!", "danger")
            return redirect(url_for("register"))

        # Перевіряємо, чи логін вже існує
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Користувач із таким логіном вже існує!", "danger")
            return redirect(url_for("register"))

        # Хешуємо пароль
        hashed_password = generate_password_hash(password)

        # Створюємо заявку на реєстрацію
        new_request = RegistrationRequest(
            full_name=full_name,
            username=username,
            password_hash=hashed_password
        )
        db.session.add(new_request)
        db.session.commit()

        flash("Запит на реєстрацію відправлено! Очікуйте підтвердження адміністратора.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Сторінка адміністрування заявок
@app.route("/admin/requests")
@login_required
def admin_requests():
    if current_user.username != "admin":
        flash("Доступ заборонено!", "danger")
        return redirect(url_for("home"))

    requests = RegistrationRequest.query.filter_by(approved=False).all()
    return render_template("admin_requests.html", requests=requests)

# схвалення та відхилення заявок реєстрації 
@app.route("/admin/approve/<int:request_id>")
@login_required
def approve_request(request_id):
    if current_user.username != "admin":
        return redirect(url_for("home"))

    req = RegistrationRequest.query.get(request_id)
    if req:
        new_user = User(username=req.username, password=req.password_hash)
        db.session.add(new_user)
        db.session.delete(req)
        db.session.commit()
        flash("Користувач доданий!", "success")
    
    return redirect(url_for("admin_requests"))

@app.route("/admin/reject/<int:request_id>")
@login_required
def reject_request(request_id):
    if current_user.username != "admin":
        return redirect(url_for("home"))

    req = RegistrationRequest.query.get(request_id)
    if req:
        db.session.delete(req)
        db.session.commit()
        flash("Запит відхилено!", "danger")
    
    return redirect(url_for("admin_requests"))

@app.route("/admin/employees")
@login_required
def admin_employees():
    if current_user.username != "admin":
        flash("Доступ заборонено!", "danger")
        return redirect(url_for("home"))

    users = User.query.all()  # Отримуємо всіх зареєстрованих користувачів
    return render_template("admin_employees.html", users=users)

@app.route("/admin/delete/<int:user_id>")
@login_required
def delete_employee(user_id):
    if current_user.username != "admin":
        flash("Доступ заборонено!", "danger")
        return redirect(url_for("home"))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"Користувач {user.username} був видалений!", "success")
    
    return redirect(url_for("admin_employees"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        # Перевірка правильності поточного пароля
        if not check_password_hash(current_user.password, current_password):
            flash("Неправильний поточний пароль!", "danger")
            return redirect(url_for("profile"))

        # Перевірка нового пароля
        if new_password != confirm_password:
            flash("Нові паролі не співпадають!", "danger")
            return redirect(url_for("profile"))

        # Оновлення пароля
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Пароль успішно змінено!", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html")

# # Створення форми завантаження фото для Адміна
# @app.route("/admin/upload_photo/<int:user_id>", methods=["GET", "POST"])
# @login_required
# def upload_photo(user_id):
#     if current_user.username != "admin":
#         flash("Доступ заборонено!", "danger")
#         return redirect(url_for("home"))

#     user = User.query.get(user_id)
#     if not user:
#         flash("Користувач не знайдений!", "danger")
#         return redirect(url_for("admin_employees"))

#     if request.method == "POST":
#         if "file" not in request.files:
#             flash("Файл не обрано!", "danger")
#             return redirect(request.url)

#         file = request.files["file"]

#         if file.filename == "":
#             flash("Файл не обрано!", "danger")
#             return redirect(request.url)

#         if file and allowed_file(file.filename):
#             filename = secure_filename(f"{user.username}.{file.filename.rsplit('.', 1)[1].lower()}")
#             filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
#             file.save(filepath)

#             user.profile_picture = filename
#             db.session.commit()

#             flash("Фотографія завантажена успішно!", "success")
#             return redirect(url_for("admin_employees"))

#     return render_template("upload_photo.html", user=user)

# маршрут для завантаження фото (адміном)
@app.route("/admin/upload_photo/<int:user_id>", methods=["GET", "POST"])
@login_required
def upload_photo(user_id):
    if current_user.username != "admin":
        flash("Доступ заборонено!", "danger")
        return redirect(url_for("home"))

    user = User.query.get(user_id)
    if not user:
        flash("Користувач не знайдений!", "danger")
        return redirect(url_for("admin_employees"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("Файл не обрано!", "danger")
            return redirect(request.url)

        file = request.files["file"]
        if file.filename == "":
            flash("Файл не обрано!", "danger")
            return redirect(request.url)

        if file:
            filename = secure_filename(f"{user.username}.bin")

            # Генеруємо або отримуємо AES-ключ для користувача
            if not user.aes_key_encrypted:
                aes_key = generate_aes_key()
                user.aes_key_encrypted = encrypt_aes_key(aes_key)
                db.session.commit()
            else:
                aes_key = decrypt_aes_key(user.aes_key_encrypted)

            # Генеруємо IV
            iv = os.urandom(16)

            # Читаємо файл і шифруємо його
            file_data = file.read()
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)

            # Додаємо паддінг
            def pad(data):
                return data + (16 - len(data) % 16) * b"\0"

            encrypted_image = cipher.encrypt(pad(file_data))

            # Зберігаємо файл
            with open(os.path.join("static/encrypted_photos", filename), "wb") as enc_file:
                enc_file.write(iv + encrypted_image)

            user.profile_picture = filename
            db.session.commit()

            flash("Фотографія успішно завантажена!", "success")
            return redirect(url_for("admin_employees"))

    return render_template("upload_photo.html", user=user)


# маршрут для перегляду фото користувачем
@app.route("/profile_photo")
@login_required
def profile_photo():
    user = current_user
    if not user.profile_picture:
        flash("Фото відсутнє!", "danger")
        return redirect(url_for("profile"))

    encrypted_path = os.path.join("static/encrypted_photos", user.profile_picture)

    # Перевіряємо, чи існує зашифроване фото
    if not os.path.exists(encrypted_path):
        flash("Зашифроване фото не знайдено!", "danger")
        return redirect(url_for("profile"))

    # Отримуємо AES-ключ користувача
    aes_key = decrypt_aes_key(user.aes_key_encrypted)

    # Читаємо зашифрований файл
    with open(encrypted_path, "rb") as enc_file:
        encrypted_data = enc_file.read()

    # Витягуємо IV
    iv = encrypted_data[:16]
    encrypted_image = encrypted_data[16:]

    # Дешифруємо
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_image = cipher.decrypt(encrypted_image)

    # Видаляємо паддінг
    decrypted_image = decrypted_image.rstrip(b"\0")

    # Відправляємо зображення користувачеві
    return send_file(BytesIO(decrypted_image), mimetype="image/jpeg")



if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Створення таблиці користувачів
    app.run(debug=True)