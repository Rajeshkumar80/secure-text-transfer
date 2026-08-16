import os
import os.path
import tempfile
import uuid
from flask import Flask, request, redirect, url_for, render_template, session, send_from_directory, send_file, flash, abort
from werkzeug.utils import secure_filename
import DH
import pickle
import random
from services import crypto_service

UPLOAD_FOLDER = './media/text-files/'
UPLOAD_KEY = './media/public-keys/'
ALLOWED_EXTENSIONS = set(['txt'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '5f2c9a41e8b74d06a3c1f9e0b2d8a7c6')

def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

'''
-----------------------------------------------------------
					PAGE REDIRECTS
-----------------------------------------------------------
'''
def post_upload_redirect():
	return render_template('post-upload.html')

@app.route('/register')
def call_page_register_user():
	return render_template('register.html')

@app.route('/home')
def back_home():
	return render_template('index.html')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/upload-file')
def call_page_upload():
	return render_template('upload.html')
'''
-----------------------------------------------------------
				DOWNLOAD KEY-FILE
-----------------------------------------------------------
'''
@app.route('/public-key-directory/retrieve/key/<username>')
def download_public_key(username):
	for root,dirs,files in os.walk('./media/public-keys/'):
		for file in files:
			list = file.split('-')
			if list[0] == username:
				filename = UPLOAD_KEY+file
				return send_file(filename, download_name='publicKey.pem',as_attachment=True)
	abort(404)

@app.route('/retrieve/app')
def download():
	filepath = './media/standalone/'+'app.zip'
	if(os.path.isfile(filepath)):
		return send_file(filepath, download_name='encrypt-decrypt.zip',as_attachment=True)
	else:
		return render_template('file-list.html',msg='An issue encountered, our team is working on that')

# @app.route('/file-directory/retrieve/file/<filename>')
# def download_file(filename):
# 	filepath = UPLOAD_FOLDER+filename
# 	if(os.path.isfile(filepath)):
# 		return send_file(filepath, attachment_filename='fileMessage-Security.txt',as_attachment=True)
# 	else:
# 		return render_template('file-list.html',msg='An issue encountered, our team is working on that')
@app.route('/file-directory/retrieve/file/<filename>')
def download_file(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.isfile(filepath):
        # Generate a unique filename for the downloaded file
        unique_filename = str(uuid.uuid4()) + '-' + secure_filename(filename)
        renamed_filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        os.rename(filepath, renamed_filepath)  # Rename the file
        return send_file(renamed_filepath, as_attachment=True)
    else:
        return render_template('file-list.html', msg='An issue encountered, our team is working on that')
'''
-----------------------------------------------------------
		BUILD - DISPLAY FILE - KEY DIRECTORY
-----------------------------------------------------------
'''
# Build public key directory
@app.route('/public-key-directory/')
def downloads_pk():
	username = []
	if(os.path.isfile("./media/database/database_1.pickle")):
		pickleObj = open("./media/database/database_1.pickle","rb")
		username = pickle.load(pickleObj)
		pickleObj.close()
	if len(username) == 0:
		return render_template('public-key-list.html',msg='Aww snap! No public key found in the database')
	else:
		return render_template('public-key-list.html',msg='',itr = 0, length = len(username),directory=username)

# Build file directory
@app.route('/file-directory/')
def download_f():
	for root,dirs,files in os.walk(UPLOAD_FOLDER):
		if(len(files) == 0):
			return render_template('file-list.html',msg='Aww snap! No file found in directory')
		else:
			return render_template('file-list.html',msg='',itr=0,length=len(files),list=files)

'''
-----------------------------------------------------------
				UPLOAD ENCRYPTED FILE
-----------------------------------------------------------
'''

@app.route('/data', methods=['GET', 'POST'])
def upload_file():
	if request.method == 'POST':
		# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		# if user does not select file, browser also
		# submit a empty part without filename
		if file.filename == '':
			flash('No selected file')
			return 'NO FILE SELECTED'
		if file:
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			return post_upload_redirect()
		return 'Invalid File Format !'

'''
-----------------------------------------------------------
		ENCRYPT / DECRYPT VIA crypto_service
-----------------------------------------------------------
'''

def _save_upload(request_files, field):
	if field not in request_files:
		return None, 'No file part'
	file = request_files[field]
	if file.filename == '':
		return None, 'No selected file'
	temp_path = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + '.txt')
	file.save(temp_path)
	return temp_path, None

def _form_key(form, field):
	value = form.get(field, '').strip()
	if not value:
		raise ValueError(f'Missing {field}')
	return value

@app.route('/encrypt', methods = ['POST'])
def encrypt_route():
	try:
		temp_path, err = _save_upload(request.files, 'file')
		if err:
			return {'error': err}, 400
		if not allowed_file(secure_filename(request.files['file'].filename)):
			return {'error': 'Only .txt files are accepted'}, 400
		their_public = _form_key(request.form, 'public-key')
		my_private = _form_key(request.form, 'private-key')
		key = crypto_service.derive_key(my_private, their_public)
		stem = os.path.splitext(secure_filename(request.files['file'].filename))[0]
		output_path = crypto_service.encrypt_file(
			temp_path, key,
			os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + '-encrypted.txt'))
		return send_file(output_path,
			download_name=secure_filename(stem + '-encrypted.txt'), as_attachment=True)
	except ValueError as exc:
		return {'error': str(exc)}, 400
	except Exception:
		return {'error': 'Encryption failed. Check the keys and the file.'}, 400

@app.route('/decrypt', methods = ['POST'])
def decrypt_route():
	try:
		temp_path, err = _save_upload(request.files, 'file')
		if err:
			return {'error': err}, 400
		if not allowed_file(secure_filename(request.files['file'].filename)):
			return {'error': 'Only .txt files are accepted'}, 400
		their_public = _form_key(request.form, 'public-key')
		my_private = _form_key(request.form, 'private-key')
		key = crypto_service.derive_key(my_private, their_public)
		stem = os.path.splitext(secure_filename(request.files['file'].filename))[0]
		output_path = crypto_service.decrypt_file(
			temp_path, key,
			os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + '-decrypted.txt'))
		return send_file(output_path,
			download_name=secure_filename(stem + '-decrypted.txt'), as_attachment=True)
	except ValueError as exc:
		return {'error': str(exc)}, 400
	except Exception:
		return {'error': 'Decryption failed. Check the keys and the file.'}, 400

'''
----------------------------------------------------------
REGISTER UNIQUE USERNAME AND GENERATE PUBLIC KEY WITH FILE
----------------------------------------------------------
'''

def _register_new_user(username, firstname, secondname):
	"""Register a user; returns (private_key, error). Shared by the
	HTML fallback route and the JSON API used by the single-page UI."""
	privatekeylist = []
	usernamelist = []
	# Import pickle file to maintain uniqueness of the keys
	# NOTE: pickle.load is an RCE vector when fed untrusted data. Only files
	# this app itself wrote to ./media/database/ are ever loaded here; user
	# uploads are never unpickled. Accepted academic-project trade-off,
	# not production-safe.
	if(os.path.isfile("./media/database/database.pickle")):
		pickleObj = open("./media/database/database.pickle","rb")
		privatekeylist = pickle.load(pickleObj)
		pickleObj.close()
	if(os.path.isfile("./media/database/database_1.pickle")):
		pickleObj = open("./media/database/database_1.pickle","rb")
		usernamelist = pickle.load(pickleObj)
		pickleObj.close()
	if username in usernamelist:
		return None, 'Username already exists'
	pin = int(random.randint(1,128))
	pin = pin % 64
	privatekey = DH.generate_private_key(pin)
	while privatekey in privatekeylist:
		privatekey = DH.generate_private_key(pin)
	privatekeylist.append(str(privatekey))
	usernamelist.append(username)
	pickleObj = open("./media/database/database.pickle","wb")
	pickle.dump(privatekeylist,pickleObj)
	pickleObj.close()
	pickleObj = open("./media/database/database_1.pickle","wb")
	pickle.dump(usernamelist,pickleObj)
	pickleObj.close()
	filename = UPLOAD_KEY+username+'-'+secondname.upper()+firstname.lower()+'-PublicKey.pem'
	publickey = DH.generate_public_key(privatekey)
	fileObject = open(filename,"w")
	fileObject.write(str(publickey))
	fileObject.close()
	return str(privatekey), None


@app.route('/api/register', methods = ['POST'])
def api_register():
	username = request.form.get('username', '').strip()
	firstname = request.form.get('first-name', '').strip()
	secondname = request.form.get('last-name', '').strip()
	if not (username and firstname and secondname):
		return {'error': 'All fields are required'}, 400
	privatekey, err = _register_new_user(username, firstname, secondname)
	if err:
		return {'error': err}, 400
	return {'username': username, 'private_key': privatekey}

@app.route('/api/public-keys')
def api_public_keys():
	usernamelist = []
	if(os.path.isfile("./media/database/database_1.pickle")):
		pickleObj = open("./media/database/database_1.pickle","rb")
		usernamelist = pickle.load(pickleObj)
		pickleObj.close()
	entries = []
	for username in usernamelist:
		key_text = None
		for root, dirs, files in os.walk(UPLOAD_KEY):
			for file in files:
				if file.split('-')[0] == username:
					with open(os.path.join(root, file), "r") as key_file:
						key_text = key_file.read().strip()
		entries.append({'username': username, 'public_key': key_text,
			'url': '/public-key-directory/retrieve/key/' + username})
	return entries

@app.route('/api/files')
def api_files():
	for root, dirs, files in os.walk(UPLOAD_FOLDER):
		return files
	return []

@app.route('/register-new-user', methods = ['GET', 'POST'])
def register_user():
	if request.method == 'GET':
		return render_template('register.html')
	username = request.form.get('username', '')
	firstname = request.form.get('first-name', '')
	secondname = request.form.get('last-name', '')
	privatekey, err = _register_new_user(username, firstname, secondname)
	if err:
		return render_template('register.html', name=err)
	return render_template('key-display.html', privatekey=str(privatekey))


	
if __name__ == '__main__':
	# app.run(host="0.0.0.0", port=80)
	app.run()