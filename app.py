from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv2D, Flatten, LSTM
import matplotlib.pyplot as plt
import io
import base64
import socket
import threading
from flask_socketio import SocketIO, emit
import requests
import json
import pyshark
import asyncio
import random
plt.switch_backend('Agg')  # Use the non-GUI backend

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)  # 实例化 SocketIO 对象

# FOFA API 配置信息
FOFA_EMAIL = 'your_fofa_email'
FOFA_KEY = 'your_fofa_api_key'

# 全局变量来存储结果
results_data = {}
accuracy_plot_url = ""

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.password}')"

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Login')
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha = IntegerField('Captcha', validators=[DataRequired()])
    submit = SubmitField('Login')

class PortScanForm(FlaskForm):
    target = StringField('Target', validators=[DataRequired()])
    ports = TextAreaField('Ports (comma-separated)', validators=[DataRequired()])
    submit = SubmitField('Scan')

class FOFAQueryForm(FlaskForm):
    query = StringField('Query', validators=[DataRequired()])
    submit = SubmitField('Search')

class TrafficCaptureForm(FlaskForm):
    interface = StringField('Interface', validators=[DataRequired()])
    duration = StringField('Duration (seconds)', validators=[DataRequired()])
    submit = SubmitField('Start Capture')

class BruteForceForm(FlaskForm):
    target = StringField('Target', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password_list = TextAreaField('Password List (one per line)', validators=[DataRequired()])
    submit = SubmitField('Start Brute Force')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user and bcrypt.check_password_hash(user.password, form.password.data):
#             if form.captcha.data == form.captcha_value:
#                 session['username'] = user.username
#                 flash('Login successful!', 'success')
#                 return redirect(url_for('dashboard'))  # 登录成功后重定向到/dashboard
#             else:
#                 flash('Invalid captcha', 'danger')
#         else:
#             flash('Login unsuccessful. Please check username and password', 'danger')
#     return render_template('login.html', form=form,captcha=form.captcha_value)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        form.captcha_value = random.randint(1000, 9999)
        session['captcha_value'] = form.captcha_value
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if form.captcha.data == session.get('captcha_value'):
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid captcha', 'danger')
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form, captcha=session.get('captcha_value'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/info_collection', methods=['GET', 'POST'])
def info_collection():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    form = FOFAQueryForm()
    query_results = []
    error_message = None

    if form.validate_on_submit():
        query = form.query.data
        query_results, error_message = perform_fofa_query(query)
        print(query_results)  # 调试信息

    return render_template('info_collection.html', form=form, query_results=query_results, error_message=error_message)

def perform_fofa_query(query):
    url = 'https://fofa.info/api/v1/search/all'
    encoded_query = base64.b64encode(query.encode()).decode()  # 对查询参数进行 base64 编码
    params = {
        'email': FOFA_EMAIL,
        'key': FOFA_KEY,
        'qbase64': encoded_query,
        'size': 10  # 限制返回的结果数量，可以根据需要调整
    }
    response = requests.get(url, params=params)
    print(f"Request URL: {response.url}")  # 调试信息
    print(f"Params: {params}")  # 调试信息
    if response.status_code == 200:
        response_json = response.json()
        print(f"Response: {json.dumps(response_json, indent=2)}")  # 调试信息
        results = response_json.get('results', [])
        print(f"Results: {results}")
        return results, None
    else:
        error_message = f"Error: {response.status_code}, {response.text}"
        print(error_message)  # 调试信息
        return [], error_message

@app.route('/port_scan', methods=['GET', 'POST'])
def port_scan():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    form = PortScanForm()
    scan_results = []

    if form.validate_on_submit():
        target = form.target.data
        ports = form.ports.data.split(',')
        ports = [int(port.strip()) for port in ports]
        scan_results = perform_port_scan(target, ports)

    return render_template('port_scan.html', form=form, scan_results=scan_results)

def perform_port_scan(target, ports):
    results = []
    for port in ports:
        result = scan_port(target, port)
        results.append(result)
    return results

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    try:
        s.connect((target, port))
        s.close()
        return f"Port {port} is open on {target}."
    except:
        return f"Port {port} is closed on {target}."

@app.route('/traffic_capture', methods=['GET', 'POST'])
def traffic_capture():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    form = TrafficCaptureForm()
    if form.validate_on_submit():
        interface = form.interface.data
        duration = int(form.duration.data)
        capture_file = os.path.join(app.config['UPLOAD_FOLDER'], 'capture.pcap')
        # 使用异步线程捕捉流量
        thread = threading.Thread(target=capture_traffic, args=(interface, duration, capture_file))
        thread.start()
        flash(f'Traffic capture started on {interface} for {duration} seconds.', 'success')
        return redirect(url_for('traffic_result'))

    return render_template('traffic_capture.html', form=form)

@app.route('/traffic_result')
def traffic_result():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('traffic_result.html')

def capture_traffic(interface, duration, output_file):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        capture.sniff(timeout=duration)

        # 实时发送捕捉的数据包信息到前端
        for packet in capture.sniff_continuously(packet_count=10):
            # 尝试获取更多的字段信息
            try:
                packet_info = {
                    'number': packet.number,
                    'length': packet.length,
                    'src_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                    'protocol': packet.highest_layer if hasattr(packet, 'highest_layer') else 'N/A'
                }
            except AttributeError:
                packet_info = {
                    'number': packet.number,
                    'length': packet.length,
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A',
                    'protocol': 'N/A'
                }

            socketio.emit('packet', packet_info)

        capture.close()

        # 显式地关闭事件循环之前，等待所有任务完成
        pending = asyncio.all_tasks(loop)
        if pending:
            loop.run_until_complete(asyncio.gather(*pending))
        
        loop.close()
    except pyshark.tshark.tshark.TSharkNotFoundException as e:
        print(f"TShark not found: {e}")
        socketio.emit('error', {"message": "TShark not found. Please ensure Wireshark is installed and TShark is in your PATH."})
    except Exception as e:
        print(f"Error capturing traffic: {e}")
        socketio.emit('error', {"message": "Error capturing traffic. Please check the interface and try again."})

@app.route('/password_brute_force', methods=['GET', 'POST'])
def password_brute_force():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    form = BruteForceForm()
    if form.validate_on_submit():
        target = form.target.data
        username = form.username.data
        password_list = form.password_list.data.split('\n')
        # 启动异步线程进行暴力破解
        thread = threading.Thread(target=perform_brute_force, args=(target, username, password_list))
        thread.start()
        flash('Brute force attack started.', 'success')
        return redirect(url_for('brute_force_result'))

    return render_template('password_brute_force.html', form=form)

@app.route('/brute_force_result')
def brute_force_result():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('brute_force_result.html')

@app.route('/users')
def users():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

def perform_brute_force(target, username, password_list):
    for password in password_list:
        success = attempt_login(target, username, password.strip())
        result = f"Trying password: {password.strip()} - {'Success' if success else 'Failed'}"
        print(result)  # 添加日志输出
        socketio.emit('brute_force_result', {'result': result})
        if success:
            break

# def attempt_login(target, username, password):
#     # 模拟登录尝试，这里可以根据实际需求进行实现
#     # 例如：requests.post(target, data={'username': username, 'password': password})
#     # 如果登录成功返回True，否则返回False
#     # 这个函数只是模拟总是返回False，实际应用中需要根据目标系统实现
#     return False
def attempt_login(target, username, password):
    login_url = f"http://{target}/login"
    payload = {
        'username': username,
        'password': password
    }
    
    try:
        response = requests.post(login_url, data=payload)
        if response.status_code == 200 and "Login Successful" in response.text:
            return True
        else:
            return False
    except requests.RequestException as e:
        print(f"Error during login attempt: {e}")
        return False
    
@app.route('/detect', methods=['GET', 'POST'])
def detect():
    if 'username' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        train_file = request.files['train_file']
        test_file = request.files['test_file']
        model_type = request.form['model']

        if train_file and test_file and train_file.filename.endswith('.csv') and test_file.filename.endswith('.csv'):
            train_filename = secure_filename(train_file.filename)
            test_filename = secure_filename(test_file.filename)
            train_filepath = os.path.join(app.config['UPLOAD_FOLDER'], train_filename)
            test_filepath = os.path.join(app.config['UPLOAD_FOLDER'], test_filename)
            train_file.save(train_filepath)
            test_file.save(test_filepath)

            # 加载数据集用于可视化
            train_data = pd.read_csv(train_filepath)
            test_data = pd.read_csv(test_filepath)
            train_sample = train_data.sample(n=min(100, len(train_data)))
            test_sample = test_data.sample(n=min(100, len(test_data)))

            train_stats = {
                'columns': train_sample.columns.tolist(),
                'data': train_sample.values.tolist()
            }

            test_stats = {
                'columns': test_sample.columns.tolist(),
                'data': test_sample.values.tolist()
            }

            return render_template('visualize.html', train_stats=train_stats, test_stats=test_stats, train_filepath=train_filepath, test_filepath=test_filepath, model_type=model_type)
        else:
            flash('Please upload valid CSV files for both training and testing datasets.', 'danger')
            return redirect(url_for('detect'))

    return render_template('detect.html')

@app.route('/train', methods=['POST'])
def train():
    train_filepath = request.form['train_filepath']
    test_filepath = request.form['test_filepath']
    model_type = request.form['model_type']
    
    # 启动异步任务进行模型检测
    thread = threading.Thread(target=detect_model, args=(train_filepath, test_filepath, model_type))
    thread.start()

    return render_template('training.html')

def detect_model(train_filepath, test_filepath, model_type):
    global results_data, accuracy_plot_url
    # 加载数据集
    train_data = pd.read_csv(train_filepath)
    test_data = pd.read_csv(train_filepath)
    
    # 假设数据集最后一列是标签
    x_train = train_data.iloc[:, :-1].values
    y_train = train_data.iloc[:, -1].values
    x_test = test_data.iloc[:, :-1].values
    y_test = test_data.iloc[:, -1].values

    # 根据输入数据调整形状
    if model_type == 'cnn':
        x_train = x_train.reshape(x_train.shape[0], 8, 8, 1)  # 假设是28x28的图像数据
        x_test = x_test.reshape(x_test.shape[0], 8, 8, 1)
        model = build_cnn(x_train.shape[1:])
    elif model_type == 'lstm':
        x_train = x_train.reshape((x_train.shape[0], x_train.shape[1], 1))  # 将输入数据重塑为三维
        x_test = x_test.reshape((x_test.shape[0], x_test.shape[1], 1))
        model = build_lstm(x_train.shape[1:])

    class TrainingCallback(tf.keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs=None):
            socketio.emit('training_progress', {
                'epoch': epoch + 1,
                'accuracy': logs.get('accuracy'),
                'loss': logs.get('loss'),
                'val_accuracy': logs.get('val_accuracy'),
                'val_loss': logs.get('val_loss')
            })

    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    model.fit(x_train, y_train, epochs=5, validation_data=(x_test, y_test), callbacks=[TrainingCallback()])

    loss, accuracy = model.evaluate(x_test, y_test)

    # 计算每个类别的准确率
    y_pred = np.argmax(model.predict(x_test), axis=1)
    class_accuracy = {}
    for class_label in np.unique(y_test):
        class_indices = (y_test == class_label)
        class_accuracy[class_label] = np.mean(y_pred[class_indices] == y_test[class_indices])

    # 绘制柱状图
    plt.figure(figsize=(10, 6))
    plt.bar(class_accuracy.keys(), class_accuracy.values())
    plt.xlabel('Class')
    plt.ylabel('Accuracy')
    plt.title('Accuracy per Class')

    # 保存图表为字符串
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    accuracy_plot_url = base64.b64encode(buf.getvalue()).decode('utf-8')
    buf.close()

    results_data = {
        'train_file': train_filepath,
        'test_file': test_filepath,
        'model': model.name,
        'status': f'Detection completed with accuracy: {accuracy:.2f}',
        'details': [
            {'id': 1, 'result': 'Sample result 1'},
            {'id': 2, 'result': 'Sample result 2'}
        ]
    }
    socketio.emit('training_complete')

@app.route('/results')
def results():
    global results_data, accuracy_plot_url
    if not results_data or not accuracy_plot_url:
        flash('No results to display', 'danger')
        return redirect(url_for('detect'))
    return render_template('results.html', results=results_data, accuracy_plot_url=f'data:image/png;base64,{accuracy_plot_url}')

def build_cnn(input_shape):
    model = Sequential(name='CNN')
    model.add(Conv2D(32, kernel_size=(3, 3), activation='relu', input_shape=input_shape))
    model.add(Flatten())
    model.add(Dense(10, activation='softmax'))
    return model

def build_lstm(input_shape):
    model = Sequential(name='LSTM')
    model.add(LSTM(50, input_shape=input_shape))
    model.add(Dense(10, activation='softmax'))
    return model

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()  # 确保数据库和表已创建

        # 添加一些示例数据
        if User.query.count() == 0:
            users = [
                User(username='admin', password=bcrypt.generate_password_hash('password123').decode('utf-8')),
                User(username='user1', password=bcrypt.generate_password_hash('password123').decode('utf-8')),
                User(username='user2', password=bcrypt.generate_password_hash('password123').decode('utf-8'))
            ]
            db.session.bulk_save_objects(users)
            db.session.commit()

            # 打印用户信息以验证添加
            for user in User.query.all():
                print(user)
    
    socketio.run(app, debug=True)
