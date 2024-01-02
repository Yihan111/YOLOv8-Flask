import os
import time
import pymysql
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import config
from PIL import Image
import cv2
import io
import base64
from ultralytics import YOLO

app = Flask(__name__)
app.config.from_object(config)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        # return render_template('./error/login_error.html')

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html')
        # return render_template('./error/signup_error.html')

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/upload', methods=['POST', 'GET'])  # 添加路由
def upload():
    if request.method == 'POST':
        f = request.files['file']
        user_input = request.form.get("name")
        basepath = os.path.dirname(__file__)  # 当前文件所在路径

        upload_path = os.path.join(basepath, 'static/images', secure_filename(f.filename))
        # upload_path = os.path.join(basepath, 'static/images','test.jpg')  #注意：没有的文件夹一定要先创建，不然会提示没有该路径
        f.save(upload_path)
        # 使用Opencv转换一下图片格式和名称
        img = cv2.imread(upload_path)
        cv2.imwrite(os.path.join(basepath, 'static/images', 'test.jpg'), img)

        return render_template('22.html', userinput=user_input, val1=time.time())

    return render_template('11.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/change_password_1', methods=['GET', 'POST'])
def change_password_1():
    return render_template('change_password.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    username = current_user.username
    new_password = request.form.get('new_password')
    hashed_password = generate_password_hash(new_password, method='sha256')
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': '1234',
        'database': 'test'
    }
    # 连接到 MySQL 数据库
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        # 假设表中有一个名为 users 的表，存储用户信息，包括密码字段
        # 这里假设用户的用户名为 'user123'

        # 更新用户新密码
        update_sql = "UPDATE user SET password = %s WHERE username = %s"
        cursor.execute(update_sql, (hashed_password, username))
        connection.commit()
        connection.close()
        return "Password changed successfully!"


@app.route('/detect', methods=['GET', 'POST'])
def predict():
    if request.method == 'GET':
        return render_template('detect.html')
    else:
        model = YOLO(model='yolov8n.pt')
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        print(file)

        if file.filename == '':
            flash('No image selected for uploading')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            upl_img = Image.open(file)
            extension = upl_img.format.lower()

            result = model.predict(source=upl_img)[0]
            res_img = Image.fromarray(result.plot())
            image_byte_stream = io.BytesIO()
            res_img.save(image_byte_stream, format='PNG')  # You can use a different format if desired, such as 'JPEG'
            image_byte_stream.seek(0)
            image_base64 = base64.b64encode(image_byte_stream.read()).decode('utf-8')
            return render_template('detect.html', detection_results=image_base64)


@app.route('/segment', methods=['GET', 'POST'])
def segment():
    if request.method == 'GET':
        return render_template('segment.html')
    else:
        model = YOLO(model='yolov8n-seg.pt')
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        print(file)

        if file.filename == '':
            flash('No image selected for uploading')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            upl_img = Image.open(file)
            extension = upl_img.format.lower()

            result = model.predict(source=upl_img)[0]
            res_img = Image.fromarray(result.plot())
            image_byte_stream = io.BytesIO()
            res_img.save(image_byte_stream, format='PNG')  # You can use a different format if desired, such as 'JPEG'
            image_byte_stream.seek(0)
            image_base64 = base64.b64encode(image_byte_stream.read()).decode('utf-8')
            return render_template('segment.html', detection_results=image_base64)


@app.route('/pose', methods=['GET', 'POST'])
def pose():
    if request.method == 'GET':
        return render_template('pose.html')
    else:
        model = YOLO(model='yolov8n-pose.pt')
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        print(file)

        if file.filename == '':
            flash('No image selected for uploading')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            upl_img = Image.open(file)
            extension = upl_img.format.lower()

            result = model.predict(source=upl_img)[0]
            res_img = Image.fromarray(result.plot())
            image_byte_stream = io.BytesIO()
            res_img.save(image_byte_stream, format='PNG')  # You can use a different format if desired, such as 'JPEG'
            image_byte_stream.seek(0)
            image_base64 = base64.b64encode(image_byte_stream.read()).decode('utf-8')
            return render_template('pose.html', detection_results=image_base64)





if __name__ == '__main__':
    app.run(debug=True)
