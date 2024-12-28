from flask import Flask, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
from flask_socketio import SocketIO, send
import os
import requests
import logging
from datetime import datetime
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = "my-secrets"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///video-chat.db"
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(filename='chat.log', level=logging.INFO)

METERED_SECRET_KEY = os.environ.get("METERED_SECRET_KEY")
METERED_DOMAIN = os.environ.get("METERED_DOMAIN")

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))

class Register(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  
        
    def set_password(self, password):
        self.password = generate_password_hash(password)


class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_code = db.Column(db.String(50), nullable=False)
    participants = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime)
    messages = db.relationship('MessageHistory', backref='meeting', lazy=True)


class MessageHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meeting_id = db.Column(db.Integer, db.ForeignKey('meeting.id'), nullable=False)
    sender = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

with app.app_context():
    db.create_all()

# Endpoint đăng nhập
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get('email')       
    password = data.get('password')
    
    # Kiểm tra tài khoản admin cố định
    if email == 'admin@gmail.com' and password == '123123':
        return jsonify({
            "success": True,
            "username": "admin",
            "first_name": "Admin",
            "last_name": "User",
            "role": "admin",
            "token": "dummy_token"  
        })

    user = Register.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({
            "success": True,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "username": user.username,
            "role": user.role,  # Trả về role của người dùng
            "token": "dummy_token"
        })
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


# Endpoint đăng xuất
@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True, "message": "You have been logged out successfully!"})

# Endpoint đăng ký
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    try:
        new_user = Register(
            email=data['email'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            username=data['username'],
            role='user'  # Mặc định role là 'user'
        )
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "message": "Account created successfully!"})
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Registration failed"}), 500


# Endpoint lấy thông tin người dùng
@app.route("/api/admin-login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200  # Phản hồi với status OK

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if email == "admin@gmail.com" and password == "123123":
        return jsonify({"success": True}), 200
    return jsonify({"success": False, "message": "Invalid credentials"}), 401




# Các hàm tiện ích cho upload file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"url": f"uploads/{filename}", "fileName": filename, "fileType": file.content_type}), 200
    else:
        return jsonify({"error": "File type not allowed"}), 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404



@app.route("/api/create/room", methods=['POST'])
def create_room():
    try:
        r = requests.post(f"https://{METERED_DOMAIN}/api/v1/room?secretKey={METERED_SECRET_KEY}")
        r.raise_for_status()
        data = r.json()
        room_name = data.get("roomName")

        # Create a new Meeting record
        new_meeting = Meeting(room_code=room_name, participants=1)
        db.session.add(new_meeting)
        db.session.commit()
        
        return jsonify(data)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error creating room: {e}")
        return jsonify({"error": "Failed to create room"}), 500


# Endpoint xác thực cuộc họp
@app.route("/api/validate-meeting")
def validate_meeting():
    roomName = request.args.get("roomName")
    if roomName:
        try:
            r = requests.get("https://" + METERED_DOMAIN + "/api/v1/room/" +
                             roomName + "?secretKey=" + METERED_SECRET_KEY)
            r.raise_for_status()
            data = r.json()
            if data.get("roomName"):
                return {"roomFound": True}
            else:
                return {"roomFound": False}
        except requests.exceptions.RequestException as e:
            logging.error(f"Error validating meeting: {e}")
            return jsonify({"error": "Failed to validate meeting"}), 500
    else:
        return {
            "success": False,
            "message": "Please specify roomName"
        }, 400

# SocketIO cho tin nhắn
@socketio.on('message')
def handleMessage(msg):
    timestamp = datetime.now().strftime('%H:%M:%S')
    message_with_timestamp = f"{timestamp} - {msg}"
    print('Message: ' + message_with_timestamp)
    send(message_with_timestamp, broadcast=True)

# API to save message
@app.route('/api/save-message', methods=['POST'])
def save_message():
    try:
        # Parse JSON payload
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Invalid or missing JSON payload"}), 400

        # Validate required fields
        room_code = data.get('room_code')
        sender = data.get('sender')
        message = data.get('message')

        if not room_code or not sender or not message:
            return jsonify({"success": False, "error": "Missing required fields: 'room_code', 'sender', 'message'"}), 400

        # Query the meeting by room_code
        meeting = Meeting.query.filter_by(room_code=room_code).first()
        if not meeting:
            return jsonify({"success": False, "error": "Meeting not found"}), 404

        # Save the message to the database
        new_message = MessageHistory(
            meeting_id=meeting.id,
            sender=sender,
            message=message,
            timestamp=datetime.now()
        )
        db.session.add(new_message)
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as e:
        # Log the exception (ensure logging is configured)
        app.logger.error(f"Error in save_message: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500
    
# API to updtate quantity of participants
@app.route("/api/update-participants/<room_name>", methods=["POST"])
def update_participants(room_name):
    meeting = Meeting.query.filter_by(room_code=room_name).first()
    if meeting:
        participants_count = request.json.get("participants")
        
        # Kiểm tra nếu "participants" có trong dữ liệu JSON và nó là số hợp lệ
        if participants_count is not None and isinstance(participants_count, int) and participants_count >= 0:
            meeting.participants = participants_count
            db.session.commit()
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Invalid participants count"}), 400
    return jsonify({"success": False, "error": "Meeting not found"}), 404


#aPI lấy thông tin người tham gia
@app.route("/api/meeting-participants/<room_code>", methods=["GET"])
def get_meeting_participants(room_code):
    # Tìm meeting theo room_code
    meeting = Meeting.query.filter_by(room_code=room_code).first()
    if not meeting:
        return jsonify({"success": False, "error": "Meeting not found"}), 404

    # Lấy danh sách người tham gia liên kết với meeting_id
    participants = meeting.query.filter_by(meeting_id=meeting.id).all()

    # Chuyển đổi danh sách người tham gia thành JSON
    participant_data = [
        {
            "id": participant.id,
            "name": participant.name,
            "joined_at": participant.joined_at,
            "left_at": participant.left_at
        }
        for participant in participants
    ]

    return jsonify({
        "success": True,
        "meeting_id": meeting.id,
        "room_code": meeting.room_code,
        "participants": participant_data
    })
  

# API to end meeting and update participants count
@app.route("/api/end-meeting/<room_name>", methods=["POST"])
def end_meeting(room_name):
    meeting = Meeting.query.filter_by(room_code=room_name).first()
    if meeting:
        # Cập nhật thời gian kết thúc của cuộc họp
        meeting.end_time = datetime.now()

        # Lưu các thay đổi vào cơ sở dữ liệu
        db.session.commit()

        return jsonify({"success": True, "message": "Meeting ended successfully"})
    return jsonify({"success": False, "error": "Meeting not found"}), 404




# API lấy thông tin cuộc họp
@app.route("/api/meeting-presence", methods=["GET"])
def meeting_presence():
    meetings = Meeting.query.all()
    meeting_list = []
    for meeting in meetings:
        meeting_list.append({
            "room_code": meeting.room_code,
            "participants": meeting.participants,
            "start_time": meeting.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": meeting.end_time.strftime('%Y-%m-%d %H:%M:%S') if meeting.end_time else None,
        })
    return jsonify(meeting_list)

#aPI lấy thông tin chi tiết cuộc họp
@app.route("/api/meeting-details/<room_name>", methods=["GET"])
def meeting_details(room_name):
    meeting = Meeting.query.filter_by(room_code=room_name).first()
    if meeting:
        messages = MessageHistory.query.filter_by(meeting_id=meeting.id).all()
        return jsonify({
            "room_code": meeting.room_code,
            "participants": meeting.participants,
            "start_time": meeting.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": meeting.end_time.strftime('%Y-%m-%d %H:%M:%S') if meeting.end_time else None,
            "messages": [{
                "sender": message.sender,
                "message": message.message,
                "timestamp": message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            } for message in messages]
        })
    return jsonify({"error": "Meeting not found"}), 404



# Endpoint lấy domain
@app.route("/api/metered-domain")
def get_metered_domain():
    return {"METERED_DOMAIN": METERED_DOMAIN}

@app.route("/api")
def index():
    return "Backend API is running"


if __name__ == "__main__":
    socketio.run(app, debug=True)
