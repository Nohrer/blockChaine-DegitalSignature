import json
import time
import os
import logging
from hashlib import sha256
from flask import Flask, request, render_template, redirect, flash, send_from_directory, session, url_for
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import datetime
from werkzeug.utils import secure_filename
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'motDePasseDyall3bar'  
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
app.config['SESSION_COOKIE_SECURE'] = True  # Use secure cookies in production

# Create uploads folder
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# In-memory user store 
users = {}  # {username: {"password": str, "public_key": bytes}}

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

class Blockchain:
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    def mine(self):
        if not self.unconfirmed_transactions:
            return False
        last_block = self.last_block
        new_block = Block(index=last_block.index + 1,
                         transactions=self.unconfirmed_transactions,
                         timestamp=time.time(),
                         previous_hash=last_block.hash)
        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index

# Instantiate blockchain
blockchain = Blockchain()

# Helper functions
def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def compute_file_hash(file):
    try:
        hasher = sha256()
        file.seek(0)
        while chunk := file.read(8192):
            hasher.update(chunk)
        file_hash = hasher.hexdigest()
        file.seek(0)
        return file_hash
    except Exception as e:
        logger.error(f"File hash error: {e}")
        raise

def generate_key_pair():
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key_pem, public_key_pem
    except Exception as e:
        logger.error(f"Key generation error: {e}")
        raise

def sign_document(document_hash, signed_by, for_who, private_key_pem):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        message = f"{document_hash}{signed_by}{for_who}".encode()
        signature = private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    except Exception as e:
        logger.error(f"Signature error: {e}")
        raise

def verify_signature(document_hash, signed_by, for_who, signature, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        message = f"{document_hash}{signed_by}{for_who}".encode()
        public_key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'private_key' not in session:
            flash("Please sign in to access this page")
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required")
            return redirect(url_for('signup'))
        if username in users:
            flash("Username already exists")
            return redirect(url_for('signup'))
        try:
            private_key_pem, public_key_pem = generate_key_pair()
            users[username] = {"password": password, "public_key": public_key_pem}
            session['username'] = username
            session['private_key'] = private_key_pem.decode()
            flash("Sign-up successful! Your private key has been generated.")
            return redirect(url_for('signing'))
        except Exception as e:
            flash(f"Error during sign-up: {str(e)}")
            logger.error(f"Sign-up error: {e}")
    return render_template('signup.html')

@app.route('/', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            session['username'] = username
            if 'private_key' not in session:
                try:
                    private_key_pem, _ = generate_key_pair()
                    session['private_key'] = private_key_pem.decode()
                except Exception as e:
                    flash(f"Error generating key: {str(e)}")
                    logger.error(f"Key generation error: {e}")
                    return redirect(url_for('signin'))
            flash("Signed in successfully")
            return redirect(url_for('signing'))
        flash("Invalid username or password")
    return render_template('signin.html')

@app.route('/signout')
def signout():
    session.pop('username', None)
    session.pop('private_key', None)
    flash("Signed out successfully")
    return redirect(url_for('signin'))

@app.route('/signing', methods=['GET', 'POST'])
@login_required
def signing():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file uploaded")
            return redirect(url_for('signing'))
        file = request.files['file']
        for_who = request.form.get('for_who')
        signed_by = session['username']

        if not file or not for_who:
            flash("Missing file or 'For Who' field")
            return redirect(url_for('signing'))

        if file.filename == '':
            flash("No file selected")
            return redirect(url_for('signing'))

        if not allowed_file(file.filename):
            flash("Invalid file type (only PDF and DOCX allowed)")
            return redirect(url_for('signing'))

        file_path = None
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            document_hash = compute_file_hash(file)
            private_key_pem = session['private_key'].encode()
            signature = sign_document(document_hash, signed_by, for_who, private_key_pem)
            if not verify_signature(document_hash, signed_by, for_who, signature, users[signed_by]['public_key']):
                raise Exception("Signature verification failed")
            tx_data = {
                'document_hash': document_hash,
                'filename': filename,
                'signed_by': signed_by,
                'for_who': for_who,
                'timestamp': time.time(),
                'signature': signature
            }
            blockchain.add_transaction(tx_data)
            flash("Document uploaded, please mine to confirm")
        except Exception as e:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            flash(f"Error uploading document: {str(e)}")
            logger.error(f"Upload error: {e}")
        return redirect(url_for('signing'))

    fetch_posts()
    return render_template('signing.html', posts=posts, private_key=session['private_key'])

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    verification_result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file uploaded")
            return redirect(url_for('verify'))
        file = request.files['file']
        if file.filename == '':
            flash("No file selected")
            return redirect(url_for('verify'))
        if not allowed_file(file.filename):
            flash("Invalid file type (only PDF and DOCX allowed)")
            return redirect(url_for('verify'))
        try:
            document_hash = compute_file_hash(file)
            for block in blockchain.chain:
                for tx in block.transactions:
                    if tx['document_hash'] == document_hash:
                        signed_by = tx['signed_by']
                        for_who = tx['for_who']
                        signature = tx['signature']
                        timestamp = datetime.datetime.fromtimestamp(tx['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                        public_key_pem = users.get(signed_by, {}).get('public_key')
                        if public_key_pem and verify_signature(document_hash, signed_by, for_who, signature, public_key_pem):
                            verification_result = {
                                'status': 'Valid',
                                'filename': tx['filename'],
                                'signed_by': signed_by,
                                'for_who': for_who,
                                'timestamp': timestamp
                            }
                        else:
                            verification_result = {'status': 'Invalid', 'message': 'Signature verification failed'}
                        break
                if verification_result:
                    break
            if not verification_result:
                verification_result = {'status': 'Not Found', 'message': 'Document not found in blockchain'}
        except Exception as e:
            flash(f"Verification error: {str(e)}")
            logger.error(f"Verification error: {e}")
    fetch_posts()
    return render_template('verify.html', posts=posts, verification_result=verification_result)

@app.route('/mine', methods=['GET'])
@login_required
def mine_unconfirmed_transactions():
    try:
        result = blockchain.mine()
        if not result:
            flash("No transactions to mine")
        else:
            flash(f"Block #{result} is mined.")
    except Exception as e:
        flash(f"Mining error: {str(e)}")
        logger.error(f"Mining error: {e}")
    return redirect(url_for('signing'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found")
        return redirect(url_for('signing'))

def fetch_posts():
    global posts
    posts = []
    for block in blockchain.chain:
        for tx in block.transactions:
            tx_copy = tx.copy()
            tx_copy["index"] = block.index
            tx_copy["hash"] = block.previous_hash
            tx_copy["timestamp"] = datetime.datetime.fromtimestamp(tx["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
            posts.append(tx_copy)
    posts = sorted(posts, key=lambda k: k['timestamp'], reverse=True)

# Run the Flask app
if __name__ == '__main__':
    app.run(port=5000, debug=True)