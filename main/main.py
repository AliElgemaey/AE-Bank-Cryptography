import io
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import padding as des_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask_migrate import Migrate
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bootstrap = Bootstrap(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    rsa_public_key = db.Column(db.LargeBinary, nullable=True)
    rsa_private_key = db.Column(db.LargeBinary, nullable=True)
    user_files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
    initialization_vector = db.Column(db.LargeBinary, nullable=False)
    
class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    file = db.relationship('File', backref='shared_with_users')
    shared_with = db.relationship('User', backref='shared_files')


def encrypt_file_content(file_path, des_key, iv):
    with open(file_path, 'rb') as f:
        content = f.read()
    
    # DES uses 64-bit (8 bytes) block size, adjust padding accordingly
    padder = des_padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_content = padder.update(content) + padder.finalize()

    cipher = Cipher(algorithms.TripleDES(des_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(padded_content) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_content)

def decrypt_file_content(enc_file_content, des_key, iv):
    cipher = Cipher(algorithms.TripleDES(des_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_content = decryptor.update(enc_file_content) + decryptor.finalize()

    # Unpad the decrypted content
    unpadder = des_padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    unpadded_content = unpadder.update(decrypted_padded_content) + unpadder.finalize()
    return unpadded_content

def rsa_encrypt_des_key(des_key, public_key):
    try:
        rsa_pub_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        encrypted_key = rsa_pub_key.encrypt(
            des_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[Encryption] Public Key: {public_key}")
        print(f"[Encryption] DES Key: {des_key}")
        print(f"[Encryption] Encrypted DES Key: {encrypted_key}")
        return encrypted_key
    except Exception as e:
        print(f"Error during encryption: {e}")
        raise

def rsa_decrypt_des_key(encrypted_key, private_key):
    try:
        rsa_priv_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        print(f"[Decryption] Private Key: {private_key}")
        print(f"[Decryption] Encrypted DES Key: {encrypted_key}")
        decrypted_key = rsa_priv_key.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"[Decryption] Decrypted DES Key: {decrypted_key}")
        return decrypted_key
    except ValueError as e:
        print(f"Decryption failed: {e}")
        raise ValueError("Decryption failed. Check your keys or padding.")

@app.route('/')
def home():
    return redirect(url_for('signup'))

def validate_password(password):
    if (len(password) >= 8 and
        re.search(r'[_!@#$%^&*(),.?":{}|<>]', password) and
        re.search(r'\d', password)):
        return True
    else:
        return False

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    session['_flashes'] = []  
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the password meets the policy requirements
        if not validate_password(password):
            flash('Password must be at least 8 characters long, include at least one special character and one number.')
            return redirect(url_for('signup'))

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

        new_user = User(username=username, password_hash=password_hash, rsa_public_key=public_key, rsa_private_key=private_key_pem)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'signup')
        return redirect(url_for('login'))

    return render_template('signup.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_files = File.query.filter_by(owner_id=user.id).all()
    return render_template('dashboard.html', files=user_files, username=user.username)


@app.route('/logout')
def logout():
    session.pop('user_id', None)  
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        des_key = os.urandom(24)  # TripleDES key is 24 bytes
        iv = os.urandom(8)  # DES block size is 8 bytes
        encrypt_file_content(file_path, des_key, iv)

        user = User.query.get(session['user_id'])
        encrypted_des_key = rsa_encrypt_des_key(des_key, user.rsa_public_key)

        new_file = File(file_name=filename + '.enc', owner_id=user.id, encrypted_aes_key=encrypted_des_key, initialization_vector=iv)
        db.session.add(new_file)
        db.session.commit()

        os.remove(file_path)
        flash('File uploaded and encrypted successfully!', 'upload')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(file_name=filename, owner_id=session['user_id']).first()
    if file_record:
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(enc_file_path, 'rb') as enc_file:
            encrypted_content = enc_file.read()

        user = User.query.get(session['user_id'])
        decrypted_des_key = rsa_decrypt_des_key(file_record.encrypted_aes_key, user.rsa_private_key)
        decrypted_content = decrypt_file_content(encrypted_content, decrypted_des_key, file_record.initialization_vector)

        return send_file(io.BytesIO(decrypted_content), download_name=filename.replace('.enc', ''), as_attachment=True)

    flash("You don't have access to this file.")
    return redirect(url_for('dashboard'))

@app.route('/download_shared/<filename>', methods=['GET'])
def download_shared(filename): 
    if 'user_id' not in session:
        return redirect(url_for('login'))

    
    file_record = File.query.filter_by(file_name=filename).first()

    if file_record:
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(enc_file_path, 'rb') as enc_file:
            encrypted_content = enc_file.read()

        
        user = User.query.get(session['user_id'])
        decrypted_des_key = rsa_decrypt_des_key(file_record.encrypted_aes_key, user.rsa_private_key)
        decrypted_content = decrypt_file_content(encrypted_content, decrypted_des_key, file_record.initialization_vector)

        return send_file(io.BytesIO(decrypted_content), download_name=filename.replace('.enc', ''), as_attachment=True)

    flash("File not found or you don't have permission to download it.")
    return redirect(url_for('shared_with_me'))


@app.route('/share/<filename>', methods=['GET', 'POST'])
def share_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        shared_with_username = request.form['shared_with_username']
        user_to_share = User.query.filter_by(username=shared_with_username).first()

        if user_to_share:
            file_record = File.query.filter_by(file_name=filename, owner_id=session['user_id']).first()

            if file_record:
                # Check if the file is already shared with this user
                already_shared = SharedFile.query.filter_by(file_id=file_record.id, shared_with_id=user_to_share.id).first()
                if already_shared:
                    flash(f'File "{filename}" is already shared with {shared_with_username}.', 'share')
                else:
                    # Add an entry in the SharedFile table to record the shared file
                    new_shared_file = SharedFile(file_id=file_record.id, shared_with_id=user_to_share.id)
                    db.session.add(new_shared_file)
                    db.session.commit()

                    flash(f'File "{filename}" has been shared with {shared_with_username}!', 'share')
            else:
                flash("File not found.", 'share')
        else:
            flash(f"User '{shared_with_username}' not found.", 'share')
        return redirect(url_for('dashboard'))

    return render_template('share_file.html', filename=filename)


@app.route('/shared_with_me', methods=['GET'])
def shared_with_me():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch the shared files for the user
    shared_files = SharedFile.query.filter_by(shared_with_id=session['user_id']).all()

    # Render the shared files
    return render_template('shared_with_me.html', shared_files=shared_files)

@app.route('/download_shared_file/<filename>', methods=['GET'])
def download_shared_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Find the shared file record based on filename and the current user
    shared_file = SharedFile.query.filter_by(shared_with_id=session['user_id']).join(File).filter_by(file_name=filename).first()

    if shared_file:
        file_record = shared_file.file
        enc_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.file_name)

        if os.path.exists(enc_file_path):
            with open(enc_file_path, 'rb') as enc_file:
                encrypted_content = enc_file.read()

            # Use the recipient's private key to decrypt the DES key
            user = User.query.get(session['user_id'])
            decrypted_des_key = rsa_decrypt_des_key(file_record.encrypted_aes_key, user.rsa_private_key)

            if decrypted_des_key:
                decrypted_content = decrypt_file_content(encrypted_content, decrypted_des_key, file_record.initialization_vector)
                return send_file(io.BytesIO(decrypted_content), download_name=filename.replace('.enc', ''), as_attachment=True)

            flash("Decryption failed. Please check the encryption keys.")
        else:
            flash("Encrypted file not found.")
    else:
        flash("You don't have access to this file.")

    return redirect(url_for('shared_with_me'))





@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Find the file by filename and owner
    file_record = File.query.filter_by(file_name=filename, owner_id=session['user_id']).first()
    if file_record:
        # Delete all related shared records
        SharedFile.query.filter_by(file_id=file_record.id).delete()

        # Delete the file from the upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Remove the file record from the database
        db.session.delete(file_record)
        db.session.commit()

        flash(f"File '{filename}' has been deleted successfully.")
    else:
        flash("File not found or you don't have permission to delete it.")

    return redirect(url_for('dashboard'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    app.run(debug=True)
