from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Lost_Item, Found_Item, Match, Message
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import uuid
from nlp_processor import calculate_similarity
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MYSQL_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

# Create tables
with app.app_context():
    db.create_all()

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def send_match_notification(user_email, lost_item, found_item, similarity_score):
    try:
        msg = Message(
            subject="Potential Match Found for Your Lost Item",
            recipients=[user_email],
            body=f"""
            Good news! We've found a potential match for your lost item.
            
            Your lost item: {lost_item.name}
            Found item: {found_item.name}
            Similarity score: {similarity_score:.2f}
            
            Please log in to your account to view more details and claim your item.
            """,
            html=f"""
            <h2>Good news! We've found a potential match for your lost item.</h2>
            <p><strong>Your lost item:</strong> {lost_item.name}</p>
            <p><strong>Found item:</strong> {found_item.name}</p>
            <p><strong>Similarity score:</strong> {similarity_score:.2f}</p>
            <p>Please <a href="{os.environ.get('FRONTEND_URL')}/login">log in to your account</a> to view more details and claim your item.</p>
            """
        )
        mail.send(msg)
        logger.info(f"Match notification email sent to {user_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({"error": "Email already registered"}), 400
    
    # Create new user
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        is_admin=data.get('is_admin', False)
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    
    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify({
        "token": access_token,
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "is_admin": user.is_admin
    }), 200

@app.route('/api/lost-items', methods=['POST'])
@jwt_required()
def report_lost_item():
    user_id = get_jwt_identity()
    
    # Handle form data and file upload
    name = request.form.get('name')
    description = request.form.get('description')
    date_lost = request.form.get('date_lost')
    
    if not all([name, description, date_lost]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Process date
    try:
        date_lost_obj = datetime.strptime(date_lost, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    # Handle image upload
    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_path = f"/uploads/{filename}"
    
    # Create lost item
    lost_item = Lost_Item(
        user_id=user_id,
        name=name,
        description=description,
        date_lost=date_lost_obj,
        image=image_path,
        status='pending'
    )
    
    db.session.add(lost_item)
    db.session.commit()
    
    # Check for potential matches with found items
    found_items = Found_Item.query.filter_by(status='approved').all()
    for found_item in found_items:
        similarity_score = calculate_similarity(lost_item.description, found_item.description)
        
        if similarity_score >= 0.8:
            # Create a match record
            match = Match(
                lost_item_id=lost_item.id,
                found_item_id=found_item.id,
                similarity_score=similarity_score
            )
            db.session.add(match)
            
            # Notify the user who reported the lost item
            user = User.query.get(user_id)
            send_match_notification(user.email, lost_item, found_item, similarity_score)
    
    db.session.commit()
    
    return jsonify({
        "message": "Lost item reported successfully",
        "item_id": lost_item.id
    }), 201

@app.route('/api/found-items', methods=['POST'])
@jwt_required()
def report_found_item():
    user_id = get_jwt_identity()
    
    # Handle form data and file upload
    name = request.form.get('name')
    description = request.form.get('description')
    date_found = request.form.get('date_found')
    
    if not all([name, description, date_found]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Process date
    try:
        date_found_obj = datetime.strptime(date_found, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    # Handle image upload
    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_path = f"/uploads/{filename}"
    
    # Create found item
    found_item = Found_Item(
        user_id=user_id,
        name=name,
        description=description,
        date_found=date_found_obj,
        image=image_path,
        status='pending'
    )
    
    db.session.add(found_item)
    db.session.commit()
    
    return jsonify({
        "message": "Found item reported successfully",
        "item_id": found_item.id
    }), 201

@app.route('/api/lost-items', methods=['GET'])
@jwt_required()
def get_lost_items():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Admin can see all items, regular users only see their own and approved items
    if user.is_admin:
        items = Lost_Item.query.all()
    else:
        items = Lost_Item.query.filter(
            (Lost_Item.user_id == user_id) | (Lost_Item.status == 'approved')
        ).all()
    
    result = []
    for item in items:
        result.append({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "date_lost": item.date_lost.strftime('%Y-%m-%d'),
            "image": item.image,
            "status": item.status,
            "user_id": item.user_id
        })
    
    return jsonify(result), 200

@app.route('/api/found-items', methods=['GET'])
@jwt_required()
def get_found_items():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    # Admin can see all items, regular users only see their own and approved items
    if user.is_admin:
        items = Found_Item.query.all()
    else:
        items = Found_Item.query.filter(
            (Found_Item.user_id == user_id) | (Found_Item.status == 'approved')
        ).all()
    
    result = []
    for item in items:
        result.append({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "date_found": item.date_found.strftime('%Y-%m-%d'),
            "image": item.image,
            "status": item.status,
            "user_id": item.user_id
        })
    
    return jsonify(result), 200

@app.route('/api/admin/approve-item/<item_type>/<int:item_id>', methods=['PUT'])
@jwt_required()
def approve_item(item_type, item_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    if item_type == 'lost':
        item = Lost_Item.query.get(item_id)
        if not item:
            return jsonify({"error": "Lost item not found"}), 404
        
        item.status = 'approved'
        db.session.commit()
        
        # Check for potential matches with found items
        found_items = Found_Item.query.filter_by(status='approved').all()
        for found_item in found_items:
            similarity_score = calculate_similarity(item.description, found_item.description)
            
            if similarity_score >= 0.8:
                # Create a match record
                match = Match(
                    lost_item_id=item.id,
                    found_item_id=found_item.id,
                    similarity_score=similarity_score
                )
                db.session.add(match)
                
                # Notify the user who reported the lost item
                item_user = User.query.get(item.user_id)
                send_match_notification(item_user.email, item, found_item, similarity_score)
        
        db.session.commit()
        
    elif item_type == 'found':
        item = Found_Item.query.get(item_id)
        if not item:
            return jsonify({"error": "Found item not found"}), 404
        
        item.status = 'approved'
        db.session.commit()
        
        # Check for potential matches with lost items
        lost_items = Lost_Item.query.filter_by(status='approved').all()
        for lost_item in lost_items:
            similarity_score = calculate_similarity(lost_item.description, item.description)
            
            if similarity_score >= 0.8:
                # Create a match record
                match = Match(
                    lost_item_id=lost_item.id,
                    found_item_id=item.id,
                    similarity_score=similarity_score
                )
                db.session.add(match)
                
                # Notify the user who reported the lost item
                lost_item_user = User.query.get(lost_item.user_id)
                send_match_notification(lost_item_user.email, lost_item, item, similarity_score)
        
        db.session.commit()
    
    else:
        return jsonify({"error": "Invalid item type"}), 400
    
    return jsonify({"message": f"{item_type.capitalize()} item approved successfully"}), 200

@app.route('/api/admin/reject-item/<item_type>/<int:item_id>', methods=['PUT'])
@jwt_required()
def reject_item(item_type, item_id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    
    if item_type == 'lost':
        item = Lost_Item.query.get(item_id)
        if not item:
            return jsonify({"error": "Lost item not found"}), 404
        
        item.status = 'rejected'
    
    elif item_type == 'found':
        item = Found_Item.query.get(item_id)
        if not item:
            return jsonify({"error": "Found item not found"}), 404
        
        item.status = 'rejected'
    
    else:
        return jsonify({"error": "Invalid item type"}), 400
    
    db.session.commit()
    return jsonify({"message": f"{item_type.capitalize()} item rejected"}), 200

@app.route('/api/matches', methods=['GET'])
@jwt_required()
def get_matches():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.is_admin:
        # Admin can see all matches
        matches = Match.query.all()
    else:
        # Regular users can only see matches related to their items
        lost_item_ids = [item.id for item in Lost_Item.query.filter_by(user_id=user_id).all()]
        found_item_ids = [item.id for item in Found_Item.query.filter_by(user_id=user_id).all()]
        
        matches = Match.query.filter(
            (Match.lost_item_id.in_(lost_item_ids)) | 
            (Match.found_item_id.in_(found_item_ids))
        ).all()
    
    result = []
    for match in matches:
        lost_item = Lost_Item.query.get(match.lost_item_id)
        found_item = Found_Item.query.get(match.found_item_id)
        
        result.append({
            "id": match.id,
            "lost_item": {
                "id": lost_item.id,
                "name": lost_item.name,
                "description": lost_item.description,
                "date_lost": lost_item.date_lost.strftime('%Y-%m-%d'),
                "image": lost_item.image,
                "user_id": lost_item.user_id
            },
            "found_item": {
                "id": found_item.id,
                "name": found_item.name,
                "description": found_item.description,
                "date_found": found_item.date_found.strftime('%Y-%m-%d'),
                "image": found_item.image,
                "user_id": found_item.user_id
            },
            "similarity_score": match.similarity_score
        })
    
    return jsonify(result), 200

@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    user_id = get_jwt_identity()
    data = request.json
    
    if not all([data.get('receiver_id'), data.get('text')]):
        return jsonify({"error": "Missing required fields"}), 400
    
    message = Message(
        sender_id=user_id,
        receiver_id=data['receiver_id'],
        text=data['text'],
        date_sent=datetime.now()
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({
        "message": "Message sent successfully",
        "message_id": message.id
    }), 201

@app.route('/api/messages', methods=['GET'])
@jwt_required()
def get_messages():
    user_id = get_jwt_identity()
    
    # Get all messages where the user is either sender or receiver
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.date_sent.asc()).all()
    
    result = []
    for msg in messages:
        sender = User.query.get(msg.sender_id)
        receiver = User.query.get(msg.receiver_id)
        
        result.append({
            "id": msg.id,
            "sender": {
                "id": sender.id,
                "name": sender.name
            },
            "receiver": {
                "id": receiver.id,
                "name": receiver.name
            },
            "text": msg.text,
            "date_sent": msg.date_sent.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))