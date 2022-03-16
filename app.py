from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_marshmallow import Marshmallow
from flask_socketio import SocketIO, emit

app = Flask(__name__)

cors = CORS(app, resources={r"/*": {"origins": "*"}})

app.config['SECRET_KEY'] = 'your secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
ma = Marshmallow(app)
socketio = SocketIO(app, cors_allowed_origins="*")
clients = {}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "public_id", "name", "email", "password")
        model = User


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer)
    to_user_id = db.Column(db.Integer)
    text = db.Column(db.Text)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        print(token)
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], "HS256")
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except Exception as e:
            print(e)
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/api/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    # print(user_schema.dump(current_user))
    users = User.query.filter(User.id != user_schema.dump(current_user)['id']).all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify(output)


@app.route('/api/users/me', methods=['GET'])
@token_required
def get_user_info(current_user):

    return jsonify({
            'public_id': current_user.public_id,
            'name': current_user.name,
            'email': current_user.email
        })


@app.route('/api/login', methods=['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = User.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({
            'token': token,
            'user': {
                'public_id': user.public_id,
                'email': user.email,
                'name': user.name
            }
        }), 201)
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.form

    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    user = User.query \
        .filter_by(email=email) \
        .first()
    if not user:
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please Log in.', 202)


@app.route('/api/message', methods=['POST'])
@token_required
def add_message(current_user):
    print(user_schema.dump(current_user))

    data = request.json
    print(data['text'])
    user_to_public_id = request.args['user_id']

    user_to = User.query \
        .filter_by(public_id=user_to_public_id) \
        .first()
    if not user_to:
        return make_response('There is no user', 404)
    print(current_user.id)
    print(user_to.id)
    message = Message(
        text=data['text'],
        from_user_id=current_user.id,
        to_user_id=user_to.id
    )
    db.session.add(message)
    db.session.commit()

    # emit('message', {'data': data['text']})

    return make_response('Successfully sent.', 201)


@app.route('/api/message', methods=['GET'])
@token_required
def get_messages(current_user):
    my_user = user_schema.dump(current_user)
    user_to_public_id = request.args['user_id']

    second_user = User.query \
        .filter_by(public_id=user_to_public_id) \
        .first()
    if not second_user:
        return make_response('There is no user', 404)
    print(current_user.id)
    print(second_user.id)

    messages = Message.query.filter((Message.from_user_id == current_user.id) & (Message.to_user_id == second_user.id)
                                    | (Message.from_user_id == second_user.id) & (
                                                Message.to_user_id == current_user.id)).all()

    print(messages)
    output = []
    for message in messages:
        output.append({
            'from': my_user['public_id'] if message.from_user_id == my_user['id'] else second_user.public_id,
            'to': my_user['public_id'] if message.to_user_id == my_user['id'] else second_user.public_id,
            'text': message.text
        })

    return jsonify(output)


@app.route('/api/message/all', methods=['GET'])
def get_all_messages():
    messages = Message.query.all()

    output = []
    for message in messages:
        output.append({
            'from': message.from_user_id,
            'to': message.to_user_id,
            'text': message.text
        })

    print(output)

    return jsonify(output)


@socketio.on('connected')
@token_required
def connected(current_user):
    print('CONNECTED!!')
    if request.sid and user_schema.dump(current_user)['public_id']:
        clients[user_schema.dump(current_user)['public_id']] = request.sid

    print(clients)


@socketio.on('json')
@token_required
def handle_send_message(current_user, json):
    print('[HANDLE SEND MESSAGE]')
    current_user_id = user_schema.dump(current_user)['public_id']
    print('Current user: ' + current_user_id)
    if 'to' in json:
        to = json['to']
        text = json['text']
        user_to = User.query \
            .filter_by(public_id=json['to']) \
            .first()
        print('User to: ' + user_to.public_id)
        print('Text: ' + text)
        message = Message(
            text=json['text'],
            from_user_id=current_user.id,
            to_user_id=user_to.id
        )
        db.session.add(message)
        db.session.commit()
        if to in clients:
            emit('message', {
                'text': str(text),
                'from': str(current_user_id),
                'to': str(to)
            }, to=clients[to])
    # else:
    #     text = json['text']
    #     emit('message', {
    #         'text': str(text),
    #         'from': str(current_user_id)
    #     }, to="global")


if __name__ == "__main__":
    socketio.run(app)
