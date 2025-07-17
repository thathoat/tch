from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
import random
import string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_W0qZF8vSiQxX@ep-rough-bonus-a1zohs9t-pooler.ap-southeast-1.aws.neon.tech:5432/neondb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # 请替换为安全的随机字符串

db = SQLAlchemy(app)
jwt = JWTManager(app)

# 数据模型
class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    users = db.relationship('User', backref='group', lazy=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('groups.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    whispers = db.relationship('Whisper', backref='user', lazy=True)

class Whisper(db.Model):
    __tablename__ = 'whisper'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# 初始化管理员账号
def init_admin_account():
    try:
        with app.app_context():
            # 检查是否已有管理员账号
            admin = User.query.filter_by(is_admin=True).first()
            if not admin:
                print("开始创建管理员账号...")
                
                # 确保吐槽组存在
                group = Group.query.filter_by(code="ADMIN123").first()
                if not group:
                    # 自动生成唯一ID
                    group_id = str(uuid.uuid4())
                    group = Group(
                        id=group_id,
                        name="管理员组",
                        code="ADMIN123"
                    )
                    db.session.add(group)
                    db.session.commit()
                    print(f"创建吐槽组 ID={group_id}, Code=ADMIN123")
                
                # 创建管理员账号
                admin_email = "admin@example.com"
                admin_password = "admin123"
                hashed_password = generate_password_hash(admin_password, method='sha256')
                
                admin = User(
                    email=admin_email,
                    password_hash=hashed_password,
                    group_id=group.id,
                    is_admin=True
                )
                
                db.session.add(admin)
                db.session.commit()
                print(f"✅ 管理员账号创建成功: {admin_email} / {admin_password}")
            else:
                print(f"✅ 管理员账号已存在: {admin.email}")
    except Exception as e:
        print(f"❌ 管理员账号创建失败: {str(e)}")
        db.session.rollback()

# 认证接口
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"message": "认证失败"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({
        "user": {
            "id": user.id,
            "email": user.email,
            "group_id": user.group_id,
            "is_admin": user.is_admin
        },
        "token": access_token
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    group_code = data.get('group_code')
    
    print(f"注册请求 - 邮箱: {email}, 组代码: {group_code}")
    
    if not group_code:
        return jsonify({"message": "请提供组代码"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "邮箱已被注册"}), 400
    
    group = Group.query.filter_by(code=group_code).first()
    if not group:
        existing_codes = [g.code for g in Group.query.all()]
        print(f"无效的组代码: {group_code}, 有效代码: {existing_codes}")
        return jsonify({
            "message": "无效的组代码",
            "valid_codes": existing_codes
        }), 400
    
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(email=email, password_hash=hashed_password, group_id=group.id)
    
    db.session.add(new_user)
    db.session.commit()
    
    access_token = create_access_token(identity=new_user.id)
    return jsonify({
        "user": {
            "id": new_user.id,
            "email": new_user.email,
            "group_id": new_user.group_id,
            "is_admin": new_user.is_admin
        },
        "token": access_token
    }), 201

# 普通用户接口
@app.route('/api/whispers', methods=['GET'])
@jwt_required()
def get_whispers():
    whispers = Whisper.query.order_by(Whisper.created_at.desc()).all()
    return jsonify([{
        "id": w.id,
        "content": w.content,
        "createdAt": w.created_at.isoformat()
    } for w in whispers]), 200

@app.route('/api/whispers', methods=['POST'])
@jwt_required()
def create_whisper():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')
    
    new_whisper = Whisper(content=content, user_id=current_user_id)
    db.session.add(new_whisper)
    db.session.commit()
    
    return jsonify({
        "id": new_whisper.id,
        "content": new_whisper.content,
        "createdAt": new_whisper.created_at.isoformat()
    }), 201

# 管理员接口
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_admin:
        return jsonify({"message": "需要管理员权限"}), 403
    
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "group_id": u.group_id,
        "group_code": u.group.code if u.group else None,  # 新增：返回组代码
        "is_admin": u.is_admin
    } for u in users]), 200

@app.route('/api/admin/groups', methods=['GET'])
@jwt_required()
def get_groups():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_admin:
        return jsonify({"message": "需要管理员权限"}), 403
    
    groups = Group.query.all()
    return jsonify([{
        "id": g.id,
        "name": g.name,
        "code": g.code,
        "createdAt": g.created_at.isoformat()
    } for g in groups]), 200

@app.route('/api/admin/whispers', methods=['GET'])
@jwt_required()
def get_admin_whispers():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_admin:
        return jsonify({"message": "需要管理员权限"}), 403
    
    whispers = Whisper.query.order_by(Whisper.created_at.desc()).all()
    return jsonify([{
        "id": w.id,
        "content": w.content,
        "userId": w.user_id,
        "user_email": w.user.email if w.user else None,  # 新增：返回用户邮箱
        "createdAt": w.created_at.isoformat()
    } for w in whispers]), 200

@app.route('/api/admin/users', methods=['POST'])
@jwt_required()
def create_user():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_admin:
        return jsonify({"message": "需要管理员权限"}), 403
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    group_code = data.get('group_code')  # 使用 group_code 而非 group_id
    is_admin = data.get('is_admin', False)
    
    print(f"管理员创建用户 - 邮箱: {email}, 组代码: {group_code}")
    
    if not group_code:
        return jsonify({"message": "请提供组代码"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "邮箱已被注册"}), 400
    
    group = Group.query.filter_by(code=group_code).first()
    if not group:
        existing_codes = [g.code for g in Group.query.all()]
        return jsonify({
            "message": "无效的组代码",
            "valid_codes": existing_codes
        }), 400
    
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(
        email=email,
        password_hash=hashed_password,
        group_id=group.id,  # 保存真实的 group_id
        is_admin=is_admin
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        "id": new_user.id,
        "email": new_user.email,
        "group_id": new_user.group_id,
        "group_code": group.code,  # 返回组代码供前端显示
        "is_admin": new_user.is_admin
    }), 201

@app.route('/api/admin/groups', methods=['POST'])
@jwt_required()
def create_group():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_admin:
        return jsonify({"message": "需要管理员权限"}), 403
    
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({"message": "组名称不能为空"}), 400
    
    # 自动生成唯一的组code（格式：GRP + 6位随机字母数字）
    def generate_code():
        characters = string.ascii_uppercase + string.digits
        return 'GRP' + ''.join(random.choices(characters, k=6))  # 例如：GRP7A2B9C
    
    # 确保code唯一（最多尝试10次）
    max_attempts = 10
    for _ in range(max_attempts):
        code = generate_code()
        if not Group.query.filter_by(code=code).first():
            break
    else:
        return jsonify({"message": "无法生成唯一的组代码"}), 500
    
    new_group = Group(
        name=name,
        code=code,
        created_at=datetime.datetime.utcnow()
    )
    
    db.session.add(new_group)
    db.session.commit()
    
    return jsonify({
        "id": new_group.id,
        "name": new_group.name,
        "code": new_group.code,
        "createdAt": new_group.created_at.isoformat()
    }), 201

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_admin_account()  # 初始化管理员账号
    app.run(debug=True)