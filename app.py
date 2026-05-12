
"""
SECURE FILE SHARING PLATFORM
"""
# shar7 el code: steps:
# 1.User registers with username and strong password
# 2.User logs in (session created)
# 3.User uploads file (automatically encrypted with AES-256)
# 4.User can share file with another user (choose view only or view+download)
# 5.Recipient can view or download based on permission
# 6.All actions are logged to audit log with IP address and timestamp
# 7.User can logout (session cleared) 
# -----------------------------------------------------------------------------------------------------------------------
# import Flask, render_template, request, redirect, session, flash, send_file:
# Flask: El framework el by5aleena n3mel web application (website)
# render_template: El function el by5aleena neshof HTML pages (like login, ..)
# request: begeb el data w mein el form 
# redirect: byeb3at el user la saf7a tany
# session: by5aleena n7afez 3ala el user logged in (ya3ni ma y7tagsh yelogin kol mara)
# flash: by5aleena nshow messages (success, error) 3ala el page
# send_file: beb3at el files lel browser 3lshan yeshofha aw ye download it
from flask import Flask, render_template, request, redirect, session, flash, send_file

# import generate_password_hash, check_password_hash
# generate_password_hash: be Scrambles el password abl ma ya3melha save fel database
# check_password_hash: be Check lw el entered password matches the scrambled one
from werkzeug.security import generate_password_hash, check_password_hash
# import: db, User, File, Share, AuditLog (el tables el 3amlenha fi file el database)
# db: The database connection
# User: Table for user accounts
# File: Table for uploaded files
# Share: Table for sharing permissions
# AuditLog: Table for recording user actions
from DB import db, User, File, Share, AuditLog

# encryption_file: be Scrambles el file content be AES-256 (be3mel encryption lel file)
# decrypt_file: be Unscrambles el file content be el password (be3mel decryption)
from encryption import encrypt_file, decrypt_file

# check_password_strength: be Check if password is strong enough (8+ chars, uppercase, etc)
from password_generator import check_password_strength

# os: 3lshan ye create folders and file paths
import os

# datetime: 3lshan ye record lama 7aga te7sal
from datetime import datetime

# io: 3lshan ab3at file content to browser
import io


# STEP 2: CREATE THE FLASK APP
# Create the web application
app = Flask(__name__)

# Secret key: be protect user sessions (like a master password for login cookies)
app.secret_key = 'mysecretkey123'

# Database location: SQLite be create file called database.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Create folder to store encrypted files (if it doesn't exist)
os.makedirs('encrypted_files', exist_ok=True)

# be Connect the database to our app
db.init_app(app)

# ========== FIX 1: ADD THIS LINE ==========
app.app_context().push()
# ==========================================

# Create all database tables (User, File, Share, AuditLog)
with app.app_context():
    db.create_all()


# STEP 3: HELPER FUNCTION: LOG USER ACTIONS
# be3mel function add_log 3lshan y record el actions eli el user 3amalha (login, upload, share, etc) 
# w ye record el wa2t eli 7asal feh el action fa ba5od el user id w el action w ba create log entry w ba saveha fel database
def add_log(user_id, action, ip_address=None):
    """
    Record what the user did in the audit log.
    Example: "User 1 logged in", "User 1 uploaded tax.pdf"
    """
    # If no IP address provided, get it from the request
    if ip_address is None:
        ip_address = request.remote_addr
    
    # Create a new log entry
    log = AuditLog(user_id=user_id, action=action, ip_address=ip_address)
    
    # Add it to the database session (prepare to save)
    db.session.add(log)
    
    # Save it permanently to the database
    db.session.commit()

# STEP 4: HOME PAGE
# be3mel home page eli lama el user yefte7 el website 
# yeb2a redirect lel login page (3lshan ma yefte7sh dashboard aw upload aw share aw view file abl ma yelogin)
@app.route('/') # el route eli lama el user yefte7 el website yero7o (http://127.0.0.1:5000/) yeb2a redirect lel login page
# be3mel function home 3lshan y redirect lel login page
def home():
    """
    When user visits the website root (http://127.0.0.1:5000/)
    Send them to the login page
    """
    return redirect('/login')


# STEP 5: LOGIN PAGE
# be3mel login page eli el user yelogin 3leha (http://127.0.0.1:5000/login) w el
# user yeb2a yekteb username w password w yelogin 3leha be method POST w lama yelogin yeb2a yeb2a redirect lel dashboard page
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page: users enter username and password
    GET: Show the login form
    POST: Process the login attempt
    """
    
    # Check if user is submitting the form (POST request)
    if request.method == 'POST':
        # Get username from the form (the input field named "username")
        username = request.form['username']
        
        # Get password from the form (the input field named "password")
        password = request.form['password']
        
        # Search database for this username
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists AND password is correct
        if user and check_password_hash(user.password_hash, password):
            # Login successful: save user info in session
            session['user_id'] = user.id        # Remember user ID
            session['username'] = user.username # Remember username
            session['password'] = password      # Remember password (for encryption)
            
            # Record this login in audit log
            add_log(user.id, 'Logged in')
            
            # Show success message
            flash('Welcome back!', 'success')
            
            # Send user to dashboard page
            return redirect('/dashboard')
        else:
            # Login failed: show error message
            flash('Wrong username or password!', 'error')
    
    # If GET request or login failed, show the login page
    return render_template('login.html')


# STEP 6: REGISTER PAGE
# be3mel register page eli el user beyekteb username w password w confirm password (ya3mel account) w yelogin 3leha be method POST 
# w lama yelogin yeb2a yeb2a redirect lel login page
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Register page: users create new account
    GET: Show registration form
    POST: Process registration
    """
    # Check if user is submitting the form
    if request.method == 'POST':
        # Get username from form
        username = request.form['username']
        
        # Get password from form
        password = request.form['password']
        
        # Get confirm password from form
        confirm = request.form['confirm_password']
        
        # ========== FIX 2: CHANGE THIS LINE ==========
        # Check if username already exists in database
        if db.session.query(User).filter_by(username=username).first():
        # =============================================
            # lw mawgod fel db haytla3 flash w yeb2a redirect lel register page tany
            flash('Username already taken!', 'error')
            return redirect('/register')
        
        # Check if password and confirm password match
        if password != confirm:
            # lw el password w confirm password mesh metshabhin haytla3 flash w yeb2a redirect lel register page tany
            flash('Passwords do not match!', 'error')
            return redirect('/register')
        
        # Check if password is strong enough
        strength = check_password_strength(password)
        if strength['score'] < 3:  # Score 0-5, need at least 3
            flash('Password too weak! Use 8+ chars, uppercase, lowercase, numbers', 'error')
            return redirect('/register')
        
        # Create new user object
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)  # Scramble password!
        )
        
        # Add to database
        # ba3mel new user object w ba add it lel database session w ba commit 3lshan a sabe it fel database
        db.session.add(new_user)
        db.session.commit()
        
        # Record registration in audit log
        add_log(new_user.id, 'Registered')
        
        # Show success message
        flash('Account created! Please login.', 'success')
        
        # Send to login page
        return redirect('/login')
    
    # If GET request, show registration form
    return render_template('register.html')


# STEP 7: DASHBOARD PAGE (Main page after login)
# be3mel dashboard page eli el user yeshof feha files eli 3ando w files eli share ma3ah w el activity log (actions eli 3amalha) 
@app.route('/dashboard')
def dashboard():
    """
    Dashboard: shows user's files, shared files, and activity log
    This is the main page users see after login
    """
    
    # Check if user is logged in (has user_id in session)
    # lw el user id mesh fel session hay redirect lel login page
    if 'user_id' not in session:
        return redirect('/login')
    
    # Get current user's ID
    user_id = session['user_id']
    
    # Get all files uploaded by this user
    my_files = File.query.filter_by(owner_id=user_id).all()
    
    # Get all files shared WITH this user
    shared_files = Share.query.filter_by(shared_with_user_id=user_id).all()
    
    # Get last 20 actions from audit log for this user (newest first)
    logs = AuditLog.query.filter_by(user_id=user_id).order_by(
        AuditLog.timestamp.desc()
    ).limit(20).all()
    
    # Show dashboard page with all the data
    return render_template('dashboard.html', 
                         my_files=my_files,
                         shared_with_me=shared_files,
                         logs=logs)

# STEP 8: UPLOAD FILE PAGE
# be3mel upload page eli el user yeb2a yeshof feha form 3lshan y upload file 
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    Upload page: user uploads a file
    GET: Show upload form
    POST: Process the uploaded file
    """
    
    # Check if user is logged in
    # bat2aked lw el user id mesh fel session hay redirect lel login page
    if 'user_id' not in session:
        return redirect('/login')
    
    # Check if user is submitting a file
    # lw el method POST hay3mel processing lel file eli et3amal upload
    if request.method == 'POST':
        # Get the uploaded file (from input field named "file")
        file = request.files.get('file')
        
        # Check if a file was actually uploaded
        if file and file.filename:
            # Step 1: Read the file content as bytes
            content = file.read()
            
            # Step 2: Get user's password from session
            password = session['password']
            
            # Step 3: ENCRYPT the file using password
            encrypted = encrypt_file(password, content)
            
            # Step 4: Create a unique filename
            # el filename el asli eli el user 3amal upload w ba3mel unique name 3lshan ma y7salsh overwrite law file tani esmo zay el file da
            # w ba3melo timestamp 3lshan yeb2a unique w ma y7salsh overwrite law file tani esmo zay el file da 
            # w 3lshan yet2aked en el file da tale3 mein el user el asly eli 3amal upload
            unique_name = f"enc_{datetime.now().timestamp()}_{file.filename}"
            path = os.path.join('encrypted_files', unique_name)
            
            # Step 5: Save encrypted file to disk
            with open(path, 'w') as f:
                f.write(encrypted)
            
            # Step 6: Save file info to database
            new_file = File(
                original_name=file.filename,
                encrypted_filename=unique_name,
                owner_id=session['user_id']
            )
            db.session.add(new_file)
            db.session.commit()
            
            # Step 7: Record in audit log
            add_log(session['user_id'], f'Uploaded {file.filename}')
            
            # Step 8: Show success message
            flash('File uploaded and encrypted!', 'success')
            
            # Step 9: Send back to dashboard
            return redirect('/dashboard')
    
    # If GET request, show upload form
    return render_template('upload.html')


# STEP 9: VIEW FILE PAGE
@app.route('/view/<int:file_id>')
def view(file_id):
    """
    View file: shows decrypted file in browser
    file_id comes from URL like /view/1
    """
    
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect('/login')
    
    # Get the file from database by its ID
    file = File.query.get_or_404(file_id)
    
    # Get current user's ID
    user_id = session['user_id']
    
    # Check if user has permission to view
    can_view = False  # Start with no permission
    
    # Permission 1: User owns the file
    # lw el owner id eli fel file besawy el user id eli fel session haytla3 can view true 
    # (3lshan el owner da2eman 3ando permission yeshof w y download el file)
    if file.owner_id == user_id:
        can_view = True
    else:
        # Permission 2: File was shared with this user
        share = Share.query.filter_by(
            file_id=file_id, 
            shared_with_user_id=user_id
        ).first()
        if share and share.can_view:
            can_view = True
    
    # If no permission, show error
    if not can_view:
        flash('No permission to view!', 'error')
        return redirect('/dashboard')
    
    try:
        # Step 1: Read encrypted file from disk
        path = os.path.join('encrypted_files', file.encrypted_filename)
        with open(path, 'r') as f:
            encrypted = f.read()
        
        # Step 2: Get user's password
        password = session['password']
        
        # Step 3: DECRYPT the file
        # be5od el password wel encrypted content w be3mel decryption
        decrypted = decrypt_file(password, encrypted)
        
        # Step 4: Record in audit log
        # ba record fe el audit log en el user da shaf el file da (file.original_name)
        add_log(user_id, f'Viewed {file.original_name}')
        
        # Step 5: Send decrypted file to browser (show, not download)
        return send_file(
            io.BytesIO(decrypted),           # File content
            download_name=file.original_name, # Original filename
            as_attachment=False              # Show in browser (not download)
        )
    except:
        # If decryption fails (wrong password or corrupted file)
        # hayrga3 error message w yeb2a redirect lel dashboard
        flash('Error decrypting file!', 'error')
        return redirect('/dashboard')


# STEP 10: SHARE FILE PAGE
# be3mel share page eli el user yeshof feha form 3lshan y share file ma3 user tani (yekteb username w y5tar permissions) 
@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share(file_id):
    """
    Share file page: user shares file with another user
    GET: Show share form
    POST: Process sharing
    """
    
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect('/login')
    
    # Get the file from database
    file = File.query.get_or_404(file_id)
    
    # Only the owner can share
    if file.owner_id != session['user_id']:
        flash('Only owner can share!', 'error')
        return redirect('/dashboard')
    
    # Check if user is submitting share form
    if request.method == 'POST':
        # Get username to share with
        username = request.form['username']
        
        # Get permissions from checkboxes (True if checked)
        can_view = 'can_view' in request.form
        can_download = 'can_download' in request.form
        
        # Find the user in database
        target = User.query.filter_by(username=username).first()
        
        # Check if user exists
        if not target:
            flash('User not found!', 'error')
            return redirect(f'/share/{file_id}')
        
        # Prevent sharing with yourself
        if target.id == session['user_id']:
            flash('You cannot share with yourself!', 'error')
            return redirect(f'/share/{file_id}')
        
        # Check if already shared
        existing = Share.query.filter_by(
            file_id=file_id,
            shared_with_user_id=target.id
        ).first()
        
        if existing:
            flash('Already shared with this user!', 'warning')
        else:
            # Create new share record
            share = Share(
                file_id=file_id,
                shared_with_user_id=target.id,
                shared_by_user_id=session['user_id'],
                can_view=can_view,
                can_download=can_download
            )
            db.session.add(share)
            db.session.commit()
            
            # Record in audit log
            add_log(session['user_id'], f'Shared {file.original_name} with {username}')
            flash(f'File shared with {username}!', 'success')
        
        return redirect('/dashboard')
    
    # If GET request, show share form
    return render_template('share.html', file=file)


# STEP 11: DOWNLOAD FILE
# be3mel download page eli el user yeb2a yeshof feha form 3lshan y download file (yeb2a forces download)
# w requires download permission
@app.route('/download/<int:file_id>')
def download(file_id):
    """
    Download file: forces browser to download the file
    Requires download permission
    """
    
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect('/login')
    
    # Get file from database
    file = File.query.get_or_404(file_id)
    user_id = session['user_id']
    
    # Check download permission
    can_download = False
    
    # Owner can always download
    if file.owner_id == user_id:
        can_download = True
    else:
        # Check if shared with download permission
        share = Share.query.filter_by(
            file_id=file_id,
            shared_with_user_id=user_id
        ).first()
        if share and share.can_download:
            can_download = True
    
    if not can_download:
        flash('No permission to download!', 'error')
        return redirect('/dashboard')
    
    try:
        # Read encrypted file
        path = os.path.join('encrypted_files', file.encrypted_filename)
        with open(path, 'r') as f:
            encrypted = f.read()
        
        # Decrypt
        # be5od el password wel encrypted content w be3mel decryption
        password = session['password']
        decrypted = decrypt_file(password, encrypted)
        
        # Record in audit log
        # ba record fe el audit log en el user da download el file da (file.original_name)
        db.session.add(AuditLog(user_id=user_id, action=f'Downloaded {file.original_name}'))
        db.session.commit()
        
        # Send as attachment (forces download)
        return send_file(
            io.BytesIO(decrypted),
            download_name=file.original_name,
            as_attachment=True  # ← This forces download
        )
    except:
        flash('Error downloading file!', 'error')
        return redirect('/dashboard')


# STEP 12: LOGOUT
# be3mel logout page w yeb3ato leha. ba clear el session
@app.route('/logout')
def logout():
    """
    Logout: clear session and send to login page
    """
    
    # Record logout if user was logged in
    if 'user_id' in session:
        add_log(session['user_id'], 'Logged out')
    
    # Clear all session data (forget user) (bs mesh mein el Database)
    session.clear()
    
    # Show message
    flash('You have been logged out.', 'info')
    
    # Send to login page
    return redirect('/login')


# STEP 13: RUN THE APP
if __name__ == '__main__':
    # Print startup message
    print()
    print("="*50)
    print("🔐 SECURE FILE SHARING PLATFORM")
    print("="*50)
    print()
    print("✅ Server started!")
    print("📍 Open: http://127.0.0.1:5000")
    print()
    print("="*50)
    print()
    
    # Start the web server
    # 
    app.run(debug=True, host='127.0.0.1', port=5000)
