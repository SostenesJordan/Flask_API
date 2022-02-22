import hashlib
from urllib import response
from flask import Flask, jsonify, request, Response, json, render_template, session, redirect, url_for, make_response
from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

from bson.objectid import ObjectId
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from datetime import datetime, timedelta
from functools import wraps
import wrapt

import requests
import mechanize
from http import cookiejar
import time


app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/Users'
app.config['SECRET_KEY'] = 'mysecret'
mongo = PyMongo(app)
# JWT Config

app.config['JWT_SECRET_KEY'] = 'this-is-secret-key'
jwt = JWTManager(app)


@app.route("/dashboard" , methods=["GET"])
@jwt_required()
def perfil():
    url = 'https://www2.detran.rn.gov.br/servicos/consultaveiculo.asp'
    data = request.form
    Placa_form, Renavam_form = data.get('placa'), data.get(
            'renavam')

    placa = Placa_form
    renavam = Renavam_form

    headers = {'User-Agent': 'Mozilla/5.0','content-type': 'application/x-www-form-urlencoded'}

    payload = {'placa':placa,'renavam':renavam,'btnConsultaPlaca':''}

    r = requests.post(url, data=payload, headers=headers)
    # print(r.text)

    rgx_modelo = re.search(
        'Marca/Modelo<BR><.*?>(.*?)</SPAN>', r.text, re.IGNORECASE)
    modelo_veiculo = rgx_modelo.group(1)

    rgx_ano_de_fabricação = re.search(
        'Fabricação/Modelo<BR><.*?>(.*?)</SPAN>', r.text, re.IGNORECASE)
    ano_de_fabricação = rgx_ano_de_fabricação.group(1)

    rgx_informacoes_pendentes = re.search(
        'Informações PENDENTES originadas das financeiras via SNG - Sistema Nacional de Gravame<BR><SPAN.*?>(.*?)</SPAN></TD>', r.text, re.IGNORECASE)
    informacoesPendentes = rgx_informacoes_pendentes.group(1)

    rgx_impedimentos = re.search(
        'Impedimentos<BR><SPAN.*?>(.*?)</SPAN></TD>', r.text, re.IGNORECASE)
    impedimentos = rgx_impedimentos.group(1)

    try:
        rgx_debitos_total = re.search('Total dos Débitos</B></TD>\s*<TD.*?><B>(.*?)</B>', r.text, re.IGNORECASE)
        debitos_total = rgx_debitos_total.group(1)
    except:
        debitos_total = False

    rgx_multas = re.search('Multas<BR><SPAN.*?>(.*?)</SPAN></TD>', r.text, re.IGNORECASE)
    multas_valor = rgx_multas.group(1)

    if not multas_valor:
        multas_valor = False

    if multas_valor.startswith('0'):
        tem_multa = False 
    else:
        tem_multa = multas_valor

    
    return jsonify({
        "modelo": modelo_veiculo,
        "ano de fabricação": ano_de_fabricação,
        "informações pendentes": informacoesPendentes,
        "impedimentos": impedimentos,
        "Multas": tem_multa,
        "Total de debitos (Licenciamento/impostos)": debitos_total,
    })
    
    # usuario = get_jwt_identity()

    # user = mongo.db.users.find_one({'nome' : usuario})

    # if user:
    #     del user["_id"], user["senha"]
    #     return  jsonify({'perfil':user}), 200

    # else:
    #     jsonify({"mensagem" : "não encontrado"}), 404



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
