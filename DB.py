# shar7 el code: ba import flask sqlalchemy bdl ma akteb sql.
# ba import datatime 3lshan lama ye7sal 7aga, ye record el wa2t eli 7asal feh ay action.
# ba Create the main database connection. el db object ha3ozo 3lshan a use it fel app.py 3lshan yekalem database.
# ba3mel awel class bekon table: User (bekon row): da haystore kol el users eli 3andena.
# kol user hayeb2a 3ando: id, username, password hash, w files eli beymlko.
# ba3mel class tanya bekon table: File (bekon row): da haystore kol el files eli 3andena.
# kol file hayeb2a 3ando: id, original name, encrypted filename, owner id, uploaded_at.
# ba3mel class tanya bekon table: Share (bekon row): da haystore kol el permissions eli 3andena.
# kol share hayeb2a 3ando: id, file_id, shared_with_user_id, shared_by_user_id, can_view, can_download, shared_at.
# w kol share hayeb2a 3ando relationships to file and users (3lshan a2dar a3raf el file w el users eli share w shared_by).
# ba3mel class tanya bekon table: AuditLog (bekon row): da haystore kol el actions eli 3andena.
# kol log hayeb2a 3ando: id, user_id, action, file_id, ip_address, timestamp.
# w kol log hayeb2a 3ando relationship to user (3lshan a2dar a3raf el user eli 3amal el action).
#-------------------------------------------------------------------------------------------------------------------------------------------------------------

"""
DATABASE MODELS FOR SECURE FILE SHARING PLATFORM
This file defines all the database tables:
1. User - Stores registered users
2. File - Stores uploaded files information
3. Share - Controls who can access which files (with permissions)
4. AuditLog - Records all actions with IP addresses
"""

# Import el database tool
from flask_sqlalchemy import SQLAlchemy

# Import datetime 3lshan automatically record when things happen
from datetime import datetime

# Create the database object (will be used in app.py)
db = SQLAlchemy()


# TABLE 1: User: Stores everyone who has an account
class User(db.Model):
    "Stores user account information. Each user who registers gets one row in this table."
    
    # ID number: unique for each user (1, 2, 3, ...)
    id = db.Column(db.Integer, primary_key=True)
    
    # Username: what the user logs in with maynfa3sh yekon null(must be unique) (max:80 characters)
    # Example: "alice", "bob",
    username = db.Column(db.String(80), unique=True, nullable=False)
    
    # Password hash: the scrambled password (never store real password!) 
    # (3lshan lw 7asal hack, el hacker msh hay3raf y3raf passwords el users) (max:200 characters)
    # Example: "pbkdf2:sha256:260000$8d969eef6e..."
    password_hash = db.Column(db.String(200), nullable=False)
    
    # This creates a relationship to files the user owns
    # ba7ot fel file (mesh real column, it's a relationship) hay link le table el file 
    # backref='owner' lets us do file.owner to get the user
    # lazy=True means it will load files only when we ask for them (not all at once) (3lshan el memory mesh aktar) 
    files = db.relationship('File', backref='owner', lazy=True)

# TABLE 2: File: Stores information about uploaded files
class File(db.Model):
    """
    Stores information about each uploaded file.
    The actual encrypted file is stored on disk, not in database.
    """
    
    # ID number: unique for each file
    id = db.Column(db.Integer, primary_key=True)
    
    # Original name: what the user named it
    # Example: "tax_return.pdf", "vacation_photo.jpg"
    original_name = db.Column(db.String(200), nullable=False)
    
    # Encrypted filename: what it's saved as on disk (bs bekon encrypted mesh besmo el asli) (max:200 characters)
    # Example: "enc_1705300000_tax_return.pdf"
    encrypted_filename = db.Column(db.String(200), nullable=False)
    
    # Owner ID: which user owns this file (links to User table)
    # Example: 1 (means user with id=1 owns this file)
    owner_id = db.Column(db.Integer, nullable=False)
    
    # When was it uploaded (automatically sets to current time)
    # default=datetime.utcnow if not specified, use the current time
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


# TABLE 3: Share: Controls who can access which files
class Share(db.Model):
    """
    Stores permission records for file sharing.
    Each row means: "This user can access this file with these permissions"
    """

    # ID number: unique for each share record
    id = db.Column(db.Integer, primary_key=True)
    
    # Stores the ID of the user who shared the file (the owner).
    file_id = db.Column(db.Integer, nullable=False)
    
    # Which user can access this file (links to User table)
    shared_with_user_id = db.Column(db.Integer, nullable=False)
    
    # Who shared this file (the owner)
    shared_by_user_id = db.Column(db.Integer, nullable=False)
    
    # PERMISSION 1: Can they VIEW the file?
    # True = can view, False = cannot view
    can_view = db.Column(db.Boolean, default=True)
    
    # PERMISSION 2: Can they DOWNLOAD the file?
    # True = can download, False = cannot download
    can_download = db.Column(db.Boolean, default=False)
    
    # When was this file shared (automatically sets to current time)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships to easily get file and user info
    # This lets us do share.file to get the file object
    file = db.relationship('File', backref='shares')
    
    # Creates a shortcut. share.shared_with gives you the User object (the person who received access).
    shared_with = db.relationship('User', foreign_keys=[shared_with_user_id])
    
    # shortcut: share.shared_by gives you the User object (the person who shared it).
    shared_by = db.relationship('User', foreign_keys=[shared_by_user_id])


# ================================================================
# TABLE 4: AuditLog - Records everything for security
# ================================================================

class AuditLog(db.Model):
    """
    Security camera - records every action users take.
    This helps track who did what, when, and from where.
    """
    
    # ID number: unique for each log entry
    id = db.Column(db.Integer, primary_key=True)
    
    # Which user performed the action (links to User table)
    user_id = db.Column(db.Integer, nullable=False)
    
    # What action did they do?
    # Examples: "login", "logout", "upload", "view", "download", "share"
    action = db.Column(db.String(200), nullable=False)
    
    # Which file was involved (can be null if action not file-related)
    # Example: 1 (means file with id=1)
    file_id = db.Column(db.Integer, nullable=True)
    
    # IP address of the user (where they are connecting from)
    # Example: "192.168.1.100" or "203.0.113.5"
    ip_address = db.Column(db.String(45), nullable=True)
    
    # When did this happen (automatically sets to current time)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to user (lets us do log.user to get user info)
    user = db.relationship('User', backref='logs')
