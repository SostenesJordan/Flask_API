import hashlib
from urllib import response
from flask import Flask, jsonify, request, Response, json, render_template, session, redirect, url_for, make_response
from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

from bson.objectid import ObjectId
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/Users'
app.config['SECRET_KEY'] = 'mysecret'
mongo = PyMongo(app)

# JWT Config
app.config["JWT_SECRET_KEY"] = "this-is-secret-key"
jwt = JWTManager(app)


@app.route("/dashboard")
@jwt_required
def dasboard():
    return jsonify(message="Welcome! to the Data Science Learner")


@app.route('/login', methods=['POST'])
def login():

    response = {
        "sucesso": False,
        "mensagem": "Parâmetros inválidos",
        "token": ""
    }

    try:
        users = mongo.db.users
        data = request.form

        if not data or not data.get('email') or not data.get('senha'):
            response["mensagem"] = "Dados invalidos"
            return response, 422

        user = users.find_one({'email': data['email']})

        if not user:
            response['mensagem'] = 'Não atutorizado'
            return response, 422

        if check_password_hash(user['senha'], data['senha']):
            # token = jwt.encode({
            #     '_id': user['_id'],
            #     'exp': datetime.utcnow() + timedelta(hours=24)
            # }, app.config['SECRET_KEY'])

            access_token = create_access_token(identity=data['senha'])

            response['mensagem'] = 'o token foi gerado'
            response['token'] = access_token
            response['exp'] = datetime.utcnow() + \
                timedelta(hours=24)
            response['sucesso'] = True

            return response, 200
            # access_token = create_access_token(
            #     identity=users.find_one({'email': data['email']}))
            # return jsonify(message="Login Succeeded!", access_token=access_token), 201

        response['mensagem'] = 'email ou senha invalido'
        return response, 403

    except Exception as ex:
        print(str(ex))
        return response, 422
    # users = mongo.db.users

    # login_user = users.find_one({'name': request.form['username']})

    # if login_user:
    #     if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):

    #         session['username'] = request.form['username']

    #         return redirect(url_for('index.html'))

    # return 'Usuario invalido'


@app.route('/registrar', methods=['POST'])
def register():

    response = {
        "sucesso": False,
        "mensagem": "Parâmetros inválidos"
    }
    try:
        users = mongo.db.users

        data = request.form

        nome, email, senha = data.get('nome'), data.get(
            'email'), data.get('senha')

        if nome == None or email == None or senha == None:
            return response, 202

        if email_valido(email) == False:
            response["mensagem"] = "Este email não está valido"
            return response, 202

        user = users.find_one({'email': email})

        if not user:
            users.insert_one({'_id': str(uuid.uuid4()), 'usuario': nome,
                             'email': email, 'senha': generate_password_hash(senha)})

            response["sucesso"] = True
            response["mensagem"] = 'Registrado com Sucesso!'

            return response, 200
        else:
            response["mensagem"] = 'usuario já exite'
            return response, 202
    except Exception as ex:
        print(str(ex))
        return response, 422

    # if request.method == 'POST':
    #     users = mongo.db.users
    #     existing_user = users.find_one({'name': request.form['username']})

    #     if existing_user is None:

    #         hashpass = bcrypt.hashpw(
    #             request.form['pass'].encode('utf-8'), bcrypt.gensalt())

    #         users.insert_one(
    #             {'name': request.form['username'],
    #              'password': hashpass})

    #         session['username'] = request.form['username']

    #         return redirect(url_for('index'))

    #     return 'Esse nome de usuario já exite'

    # return render_template('register.html')

# Utils


def email_valido(email):
    if(re.search(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\.[a-zA-Z\.a-zA-Z]{1,3}$', email)):
        return True
    else:
        return False


if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)
