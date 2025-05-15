from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    
    lost_items = db.relationship('Lost_Item', backref='user', lazy=True)
    found_items = db.relationship('Found_Item', backref='user', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

class Lost_Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_lost = db.Column(db.DateTime, nullable=False)
    image = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, claimed
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    
    matches = db.relationship('Match', backref='lost_item', lazy=True)

class Found_Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_found = db.Column(db.DateTime, nullable=False)
    image = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, claimed
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    
    matches = db.relationship('Match', backref='found_item', lazy=True)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lost_item_id = db.Column(db.Integer, db.ForeignKey('lost_item.id'), nullable=False)
    found_item_id = db.Column(db.Integer, db.ForeignKey('found_item.id'), nullable=False)
    similarity_score = db.Column(db.Float, nullable=False)
    date_matched = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
