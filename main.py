from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://server:123456@localhost/dailytracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ToBeReplacedWithPrivateKeyStoredLocally'

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

# Creating the database tables. Only use for the first time.
#with app.app_context():
#    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    hashed_password = generate_password_hash(password)
    
    new_user = Users(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email or password empty.'}), 401

    user = Users.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password_hash, password):
        token = jwt.encode({
            'user_id': user.id,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
        print('Successfully generated JWT.')
        return jsonify({'token': token})

    else:
        print('Password not match.')
        return jsonify({'message': 'User not registered or password not match.'}), 401


if __name__ == '__main__':
    app.run(debug=True)

