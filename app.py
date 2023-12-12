from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
import hashlib
import os
import uuid
from dotenv import load_dotenv
from firebase_admin import credentials, firestore, initialize_app
from firebase_config import get_firebase_config

app = Flask(__name__)
load_dotenv()

# Fungsi untuk menghasilkan token JWT dengan masa berlaku 1 hari
def generate_token(user_id):
    # Set expiration time for the token (e.g., 1 day from now)
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    
    payload = {
        'exp': expiration_time,
        'iat': datetime.datetime.utcnow(),
        'sub': str(user_id)
    }
    
    secret_key = os.getenv('SECRET_KEY')
    
    # Generate token using JWT library
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

# Inisialisasi Firebase
cred = credentials.Certificate(get_firebase_config())
initialize_app(cred)

# Inisialisasi Firestore
db = firestore.client()

last_User_Id = 0

# Middleware untuk memeriksa keberadaan token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        
        # Dapatkan token dari header request
        token = request.headers.get('Authorization')

        if not token:
            # Jika token tidak ada, kembalikan respons error
            print("Token is missing!")
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode token menggunakan secret_key
            data = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=['HS256'])
            user_id = data['sub']
            print(f"Decoded user_id: {user_id}")

            # Dapatkan referensi pengguna dari Firestore
            current_user_ref = db.collection('users').where('user_id', '==', user_id).get()

            if not current_user_ref:
                # Jika pengguna tidak ditemukan di Firestore, kembalikan respons error
                print(f"User with user_id {user_id} not found in Firestore.")
                return jsonify({'message': 'User not found!'}), 401

            # Dapatkan data pengguna saat ini
            current_user = current_user_ref[0].to_dict()
            print(f"Current user data: {current_user}")

        except jwt.ExpiredSignatureError:
            # Jika token sudah kedaluwarsa, kembalikan respons error
            print("Token has expired!")
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            # Jika token tidak valid, kembalikan respons error
            print("Invalid token!")
            return jsonify({'message': 'Invalid token!'}), 401
        else:
            # Jika tidak ada masalah, tampilkan pesan sukses
            print(f"User {current_user['Email']} successfully authenticated.")

        # Panggil fungsi route dengan argumen pengguna saat ini
        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/', methods=['GET','POST'])
def default_route():
    return jsonify({'message': 'Success fetching the API'}), 200

# API Register
@app.route('/auth/register', methods=['POST'])
def register():
    # Deklarasikan sebagai variabel global
    global last_User_Id

    # Ambil data dari JSON request
    data = request.get_json()
    Email = data.get('Email')  
    Password = data.get('Password')  
    Address = data.get('Address')  
    Age = data.get('Age')  
    Name = data.get('Name')  

    # Cek apakah Email sudah terdaftar di Firestore
    user_ref = db.collection('users').where('Email', '==', Email).get()
    if len(user_ref) > 0:
        return jsonify({'message': 'Email sudah terdaftar!'}), 400

    # Pastikan nilai Email tidak kosong
    if not Email:
        return jsonify({'message': 'Email cannot be empty!'}), 400

    # Ambil User_Id terakhir dari Firestore
    last_User_Id_ref = db.collection('users').order_by('User_Id', direction=firestore.Query.DESCENDING).limit(1).stream()
    last_User_Id = 0
    for doc in last_User_Id_ref:
        last_User_Id = doc.get('User_Id')

    # Increment User_Id
    new_User_Id = last_User_Id + 1

    # Enkripsi Password menggunakan hashlib
    hashed_password = hashlib.sha256(Password.encode()).hexdigest()

    # Menyimpan data ke Firestore
    user_data = {
        'Email': Email,
        'Password': hashed_password,
        'Address': Address,
        'Age': Age,
        'Name': Name,
        'User_Id': new_User_Id,
    }

    # Menambahkan data ke koleksi 'users'
    db.collection('users').add(user_data)
    print(f"User added to Firestore with User_Id: {new_User_Id}")

    return jsonify({'message': 'User registered successfully!'}), 201

# API Login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    Email = data.get('Email')
    Password = data.get('Password')

    print(f"Received login request with Email: {Email}, Password: {Password}")

    if not Email or not Password:
        return jsonify({'error': 'Invalid Email or Password'}), 400

    user_ref = db.collection('users').where('Email', '==', Email).get()

    print(f"Email: {Email}, User reference: {user_ref}")

    if len(user_ref) == 0:
        print(f"User with Email {Email} not found in Firestore.")
        return jsonify({'error': 'User not found'}), 404

    user_data = user_ref[0].to_dict()

    hashed_password = hashlib.sha256(Password.encode()).hexdigest()
    print(f"Hashed Password from input: {hashed_password}, Hashed Password from database: {user_data.get('Password', '')}")
    
    if hashed_password != user_data.get('Password'):
        return jsonify({'error': 'Invalid Password'}), 401

    user_id = str(user_data.get('user_id'))

    token = generate_token(user_id)

    return jsonify({
        'success': True,
        'message': 'Sukses login',
        'data': {'token': token}
    }), 200

# API untuk mendapatkan detail user dengan token yang valid
@app.route('/user/details', methods=['GET'])
@token_required
def get_user_details(current_user):
    print("Inside get_user_details")
    print(f"Current user: {current_user}")
    
    # Kembalikan detail pengguna dalam respons JSON
    return jsonify({
        'user_id': current_user.get('user_id', ''),
        'Email': current_user.get('Email', ''),
        'name': current_user.get('name', ''),
        'age': current_user.get('age', 0),
        'address': current_user.get('address', '')
    }), 200

# Jalankan aplikasi Flask jika file ini dijalankan
if __name__ == '__main__':
     app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
