from cryptography.fernet import Fernet
import sqlite3
from flask import Flask, jsonify
from flask_xmlrpcre.xmlrpcre import XMLRPCHandler, Fault
from flask_cors import CORS, cross_origin
from encryptPassword import *

app = Flask(__name__)
CORS(app, support_credentials=True)

handler = XMLRPCHandler('api')
handler.connect(app, '/')


def createDatabase():
    conn = sqlite3.connect('password_manager.db', check_same_thread=False)
    try:
        conn.execute(
            """CREATE TABLE USERS(ID INTEGER PRIMARY KEY AUTOINCREMENT, USERNAME TEXT, MAIL TEXT, PASSWORD TEXT)""")
    except:
        cursor = conn.execute("SELECT * from USERS")

    return conn


def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        generate_key()
        return open("secret.key", "rb").read()


@cross_origin(supports_credentials=True)
def add_create(addorCreate, service, url, username, password, user):
    conn = createDatabase()
    key = load_key()
    vals = {'accountName': service, 'email': username,
            'accountUrl': url, 'password': password}
    if addorCreate == 'add':
        user = 'P' + str(''.join(hex(ord(x))[2:] for x in user))
        url = str(encrypt_message(
            ''.join(hex(ord(x))[2:] for x in url), key))
        username = str(encrypt_message(
            ''.join(hex(ord(x))[2:] for x in username), key))
        service = str(encrypt_message(
            ''.join(hex(ord(x))[2:] for x in service), key))
        userkey = username + service + url
        cursor = conn.execute(
            "SELECT * FROM " + user)
        for row in cursor:
            if row[2] == userkey:
                conn.close()
                return jsonify({'returnvalue': False})

        passkey = str(encrypt_message(
            ''.join(hex(ord(x))[2:] for x in password), key))
        passkey = username + "|" + service + "|" + url + "|" + passkey
        command = 'INSERT INTO ' + user + \
            ' (USER, USERKEY, PASSWORDKEY) VALUES (?, ?, ?);'
        values = (user, userkey, passkey)
        conn.execute(command, values)
        conn.commit()
        cursor = conn.execute(
            "SELECT * FROM " + user)
        for row in cursor:
            if row[2] == userkey:
                vals['ID'] = row[0]

        conn.close()
        return jsonify({'returnvalue': True, 'values': vals})


@cross_origin(supports_credentials=True)
def update(service, url, username, password, user, id):
    conn = createDatabase()
    key = load_key()
    vals = {'accountName': service, 'email': username,
            'accountUrl': url, 'password': password}
    user = 'P' + str(''.join(hex(ord(x))[2:] for x in user))
    url = str(encrypt_message(
        ''.join(hex(ord(x))[2:] for x in url), key))
    username = str(encrypt_message(
        ''.join(hex(ord(x))[2:] for x in username), key))
    service = str(encrypt_message(
        ''.join(hex(ord(x))[2:] for x in service), key))
    userkey = username + service + url

    rows = conn.execute("SELECT * FROM " + user)
    for row in rows:
        if row[0] == id:
            passkey = str(encrypt_message(
                ''.join(hex(ord(x))[2:] for x in password), key))
            passkey = username + "|" + service + "|" + url + "|" + passkey
            command = """UPDATE """ + user + \
                """ SET USER = ?, USERKEY = ?, PASSWORDKEY = ? WHERE ID = ?;"""
            values = (user, userkey, passkey, id)
            conn.execute(command, values)
            conn.commit()
            vals['id'] = id
            return jsonify({'returnvalue': True, 'values': vals})


@cross_origin(supports_credentials=True)
def delete(id, user):
    conn = createDatabase()
    user = 'P' + str(''.join(hex(ord(x))[2:] for x in user))
    rows = conn.execute("SELECT * FROM " + user)
    for row in rows:
        if row[0] == id:
            conn.execute("DELETE FROM " + user + " WHERE ID = ?", (id,))
            conn.commit()
            return jsonify({'returnvalue': True})


@cross_origin(supports_credentials=True)
def getUsernames(user):
    lists = []
    conn = createDatabase()
    key = load_key()
    user = 'P' + str(''.join(hex(ord(x))[2:] for x in user))
    ret = conn.execute("SELECT * from " + user)
    for row in ret:
        values = []
        x = row[3].split("|")
        for i in x:
            values.append(bytes.fromhex(decrypt_message(
                bytes(i[2:-1], 'utf-8'), key)).decode('utf-8'))
        values = {'id': row[0], 'accountName': values[1], 'email': values[0],
                  'accountUrl': values[2], 'password': values[3]}
        lists.append(values)

    return jsonify({'returnvalue': lists})


@cross_origin(supports_credentials=True)
def addUser(usernameIn, mailIn, passwordIn):
    conn = createDatabase()
    key = load_key()
    mailIn = 'P' + str(''.join(hex(ord(x))[2:] for x in mailIn))
    val = True
    rows = conn.execute("SELECT * from USERS")
    for row in rows:
        if bytes.fromhex(decrypt_message(row[1], key)).decode('utf-8') == mailIn:
            val = False
            break
    if val:
        command = "CREATE TABLE " + \
            mailIn + \
            " (ID INTEGER PRIMARY KEY AUTOINCREMENT, USER TEXT , USERKEY TEXT, PASSWORDKEY TEXT)"
        conn.execute(command)
        mailIn = encrypt_message(''.join(hex(ord(x))[2:] for x in mailIn), key)
        usernameIn = encrypt_message(
            ''.join(hex(ord(x))[2:] for x in usernameIn), key)
        passwordIn = encrypt_message(
            ''.join(hex(ord(x))[2:] for x in passwordIn), key)
        command = 'INSERT INTO USERS (USERNAME, MAIL, PASSWORD) VALUES (?, ?, ?);'
        values = (usernameIn, mailIn, passwordIn)
        conn.execute(command, values)
        conn.commit()
        conn.close()
        return jsonify({'returnvalue': True})
    else:
        conn.close()
        return jsonify({'returnvalue': False})


@cross_origin(supports_credentials=True)
def userValidation(username, password):
    conn = createDatabase()
    key = load_key()
    rows = conn.execute("SELECT * from USERS")
    for row in rows:
        userRetrive = bytes.fromhex(
            decrypt_message(row[2], key)).decode('utf-8')
        if bytes.fromhex(userRetrive[1:]).decode("utf-8") == username:
            if bytes.fromhex(decrypt_message(row[3], key)).decode('utf-8') == password:
                conn.close()
                return jsonify({'returnvalue': True})
            conn.close()
            return jsonify({'returnvalue': True})
    conn.close()
    return jsonify({'returnvalue': False})


@ cross_origin(supports_credentials=True)
def forgotPassword(username):
    pass


if __name__ == '__main__':
    createDatabase()
    handler.register_function(add_create, 'addCreate')
    handler.register_function(update, 'update')
    handler.register_function(delete, 'delete')
    handler.register_function(getUsernames, 'get')
    handler.register_function(addUser, 'addUser')
    handler.register_function(userValidation, 'userValidation')
    handler.register_function(forgotPassword, 'forgotPassword')
    app.run(debug=True, host="localhost", port=5050)
