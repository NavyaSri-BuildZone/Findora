from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


# ---------------- USER ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user")  # user / admin
    points = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"


# ---------------- ITEM ----------------
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    post_type = db.Column(db.String(10), nullable=False)  # lost / found
    title = db.Column(db.String(200), nullable=False)

    category = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(100), nullable=True)

    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    is_expensive = db.Column(db.Boolean, default=False)

    image_filename = db.Column(db.String(255), nullable=True)

    status = db.Column(db.String(30), default="open")  # open / returned / archived

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="items")

    def __repr__(self):
        return f"<Item {self.title} ({self.post_type})>"


# ---------------- CLAIM ----------------
class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    item = db.relationship("Item", backref="claims")

    claimer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    finder_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    message = db.Column(db.Text, nullable=False)
    proof_answer = db.Column(db.Text, nullable=True)

    # pending -> normal waiting finder
    # admin_pending -> expensive waiting admin
    # admin_approved -> expensive approved by admin
    # finder_approved -> finder approved
    # returned -> successfully returned
    # rejected -> claim rejected
    status = db.Column(db.String(30), default="pending")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Claim {self.id} - {self.status}>"


# ---------------- RETURN LOG ----------------
class ReturnLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    claim_id = db.Column(db.Integer, db.ForeignKey("claim.id"), nullable=False)
    claim = db.relationship("Claim", backref="return_log")

    finder_confirmed = db.Column(db.Boolean, default=False)
    claimer_confirmed = db.Column(db.Boolean, default=False)

    returned_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ReturnLog claim={self.claim_id}>"


# ---------------- CHAT MESSAGES ----------------
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    claim_id = db.Column(db.Integer, db.ForeignKey("claim.id"), nullable=False)
    claim = db.relationship("Claim", backref="messages")

    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ChatMessage {self.id}>"


# ---------------- REPORTS ----------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    item = db.relationship("Item", backref="reports")

    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    reason = db.Column(db.String(200), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Report item={self.item_id}>"
