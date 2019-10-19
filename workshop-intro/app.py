import hashlib
import hmac
import datetime
import jwt
from uuid import uuid4
from os import environ as env
from chalice import Chalice, UnauthorizedError, AuthResponse


app = Chalice(app_name='workshop-intro')


@app.route('/login', methods=['POST'])
def login():
    body = app.current_request.json_body
    expected = '{}:{}'.format(env.get('username'), env.get('password'))
    actual = '{}:{}'.format(body['username'], body['password'])
    if hmac.compare_digest(actual, expected):
        now = datetime.datetime.utcnow()
        unique_id = str(uuid4())
        payload = {
            'sub': body['username'],
            'iat': now,
            'nbf': now,
            'jti': unique_id,
            # NOTE: We can also add 'exp' if we want tokens to expire.
        }
        jwt_token = jwt.encode(payload, env.get('secret'), 'HS256').decode('utf-8')
        return {'token': jwt_token}
    raise UnauthorizedError('Invalid password')


@app.authorizer()
def jwt_auth(auth_request):
    token = auth_request.token[7:]
    decoded = jwt.decode(token, env.get('secret'), algorithms=['HS256'])
    return AuthResponse(routes=['*'], principal_id=decoded['sub'])


@app.route('/', methods=['GET'], authorizer=jwt_auth)
def index():
    return {'hello': 'world'}
