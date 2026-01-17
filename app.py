import os
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime

from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Item, Claim, ReturnLog, ChatMessage, Report
from utils.decorators import admin_required

app = Flask(__name__)
app.config.from_object(Config)

# Uploads folder
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db.init_app(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Helpers ----------------
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def send_email_otp(to_email, otp):
    """
    Sends OTP to user's email using SMTP (Gmail recommended with App Password).
    Requires:
      MAIL_USERNAME, MAIL_PASSWORD in config.py or environment variables.
    """
    if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
        # fallback for testing
        print("⚠️ MAIL_USERNAME / MAIL_PASSWORD not set. OTP:", otp)
        return

    msg = EmailMessage()
    msg["Subject"] = "Findora Password Reset OTP"
    msg["From"] = app.config.get("MAIL_DEFAULT_SENDER", app.config["MAIL_USERNAME"])
    msg["To"] = to_email

    msg.set_content(
        f"Your Findora OTP is: {otp}\n\n"
        f"Do not share this OTP with anyone.\n\n"
        f"- Findora Team"
    )

    with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]) as server:
        if app.config.get("MAIL_USE_TLS", True):
            server.starttls()
        server.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
        server.send_message(msg)


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("home.html")


# ---------------- AUTH ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")

        if not name:
            flash("Name is required ❌", "danger")
            return redirect(url_for("register"))

        if not email or "@" not in email:
            flash("Enter valid email ❌", "danger")
            return redirect(url_for("register"))

        if len(mobile) != 10 or not mobile.isdigit():
            flash("Mobile number must be 10 digits ✅", "warning")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters ✅", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered ❌", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(mobile=mobile).first():
            flash("Mobile already registered ❌", "danger")
            return redirect(url_for("register"))

        new_user = User(
            name=name,
            email=email,
            mobile=mobile,
            password_hash=generate_password_hash(password),
            role="user"
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Account created ✅ Please login!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password ❌", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Logged in successfully ✅", "success")
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out ✅", "success")
    return redirect(url_for("login"))


# ---------------- FORGOT PASSWORD (EMAIL ONLY + REAL OTP EMAIL) ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not found ❌", "danger")
            return redirect(url_for("forgot_password"))

        otp = str(random.randint(100000, 999999))

        session["reset_user_id"] = user.id
        session["reset_otp"] = otp

        # ✅ Real email send
        send_email_otp(user.email, otp)

        flash("OTP sent to your email ✅", "success")
        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()

        if "reset_otp" not in session or "reset_user_id" not in session:
            flash("Session expired ❌ Try again.", "warning")
            return redirect(url_for("forgot_password"))

        if entered_otp != session["reset_otp"]:
            flash("Invalid OTP ❌", "danger")
            return redirect(url_for("verify_otp"))

        flash("OTP Verified ✅ Now set new password.", "success")
        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_user_id" not in session:
        flash("Session expired ❌ Try again.", "warning")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 8:
            flash("Password must be at least 8 characters ✅", "warning")
            return redirect(url_for("reset_password"))

        if new_password != confirm_password:
            flash("Passwords do not match ❌", "danger")
            return redirect(url_for("reset_password"))

        user = User.query.get(session["reset_user_id"])
        if not user:
            flash("User not found ❌", "danger")
            return redirect(url_for("forgot_password"))

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        session.pop("reset_user_id", None)
        session.pop("reset_otp", None)

        flash("Password reset successful ✅ Please login!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ---------------- EXPLORE (FILTERS) ----------------
@app.route("/explore")
def explore():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    post_type = request.args.get("type", "").strip()

    query = Item.query.filter(Item.status == "open")

    if q:
        query = query.filter(Item.title.ilike(f"%{q}%"))

    if category:
        query = query.filter(Item.category == category)

    if post_type in ["lost", "found"]:
        query = query.filter(Item.post_type == post_type)

    items = query.order_by(Item.created_at.desc()).all()
    return render_template("explore.html", items=items)


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)

    matches = Item.query.filter(
        Item.id != item.id,
        Item.status == "open",
        Item.category == item.category
    ).order_by(Item.created_at.desc()).limit(4).all()

    return render_template("item_detail.html", item=item, matches=matches)


# ---------------- POST LOST/FOUND ----------------
@app.route("/report-lost", methods=["GET", "POST"])
@login_required
def report_lost():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        color = request.form.get("color", "").strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()
        is_expensive = True if request.form.get("is_expensive") else False

        image = request.files.get("image")
        filename = None

        if image and image.filename and allowed_file(image.filename):
            filename = secure_filename(f"{datetime.utcnow().timestamp()}_{image.filename}")
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        item = Item(
            post_type="lost",
            title=title,
            category=category,
            color=color,
            location=location,
            description=description,
            is_expensive=is_expensive,
            image_filename=filename,
            user_id=current_user.id,
            status="open"
        )
        db.session.add(item)
        db.session.commit()

        flash("Lost item posted ✅", "success")
        return redirect(url_for("explore"))

    return render_template("report_lost.html")


@app.route("/report-found", methods=["GET", "POST"])
@login_required
def report_found():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        color = request.form.get("color", "").strip()
        location = request.form.get("location", "").strip()
        description = request.form.get("description", "").strip()
        is_expensive = True if request.form.get("is_expensive") else False

        image = request.files.get("image")
        filename = None

        if image and image.filename and allowed_file(image.filename):
            filename = secure_filename(f"{datetime.utcnow().timestamp()}_{image.filename}")
            image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        item = Item(
            post_type="found",
            title=title,
            category=category,
            color=color,
            location=location,
            description=description,
            is_expensive=is_expensive,
            image_filename=filename,
            user_id=current_user.id,
            status="open"
        )
        db.session.add(item)
        db.session.commit()

        flash("Found item posted ✅", "success")
        return redirect(url_for("explore"))

    return render_template("report_found.html")


# ---------------- CLAIM (ONLY FOUND ITEMS) ----------------
@app.route("/claim/<int:item_id>", methods=["GET", "POST"])
@login_required
def claim_item(item_id):
    item = Item.query.get_or_404(item_id)

    if item.post_type != "found":
        flash("Only FOUND items can be claimed ✅", "warning")
        return redirect(url_for("item_detail", item_id=item.id))

    if item.status != "open":
        flash("This post is already closed ✅", "info")
        return redirect(url_for("item_detail", item_id=item.id))

    if item.user_id == current_user.id:
        flash("You cannot claim your own post ❌", "danger")
        return redirect(url_for("item_detail", item_id=item.id))

    if request.method == "POST":
        message = request.form.get("message", "").strip()
        proof_answer = request.form.get("proof_answer", "").strip()

        status = "admin_pending" if item.is_expensive else "pending"

        new_claim = Claim(
            item_id=item.id,
            claimer_id=current_user.id,
            finder_id=item.user_id,
            message=message,
            proof_answer=proof_answer,
            status=status
        )
        db.session.add(new_claim)
        db.session.commit()

        flash("Claim submitted ✅", "success")
        return redirect(url_for("my_claims"))

    return render_template("claim_item.html", item=item)


@app.route("/my-claims")
@login_required
def my_claims():
    claims = Claim.query.filter_by(claimer_id=current_user.id).order_by(Claim.created_at.desc()).all()
    return render_template("my_claims.html", claims=claims)


@app.route("/finder-claims")
@login_required
def finder_claims():
    claims = Claim.query.filter_by(finder_id=current_user.id).order_by(Claim.created_at.desc()).all()
    return render_template("finder_claims.html", claims=claims)


@app.route("/finder-claim-action/<int:claim_id>/<action>")
@login_required
def finder_claim_action(claim_id, action):
    claim = Claim.query.get_or_404(claim_id)

    if claim.finder_id != current_user.id:
        flash("Access denied ❌", "danger")
        return redirect(url_for("home"))

    # expensive requires admin approval before finder approves
    if claim.item.is_expensive and claim.status != "admin_approved":
        flash("This expensive item needs Admin approval first 🔐", "warning")
        return redirect(url_for("finder_claims"))

    if action == "approve":
        claim.status = "finder_approved"
        flash("Claim approved ✅ Now return confirmation can be done.", "success")
    elif action == "reject":
        claim.status = "rejected"
        flash("Claim rejected ❌", "danger")

    db.session.commit()
    return redirect(url_for("finder_claims"))


# ---------------- ADMIN CLAIMS (EXPENSIVE) ----------------
@app.route("/admin/claims")
@admin_required
def admin_claims():
    claims = Claim.query.filter_by(status="admin_pending").order_by(Claim.created_at.desc()).all()
    return render_template("admin_claims.html", claims=claims)


@app.route("/admin/claim-action/<int:claim_id>/<action>")
@admin_required
def admin_claim_action(claim_id, action):
    claim = Claim.query.get_or_404(claim_id)

    if claim.status != "admin_pending":
        flash("Not pending admin approval.", "warning")
        return redirect(url_for("admin_claims"))

    if action == "approve":
        claim.status = "admin_approved"
        flash("Admin approved ✅ Finder can now approve.", "success")
    else:
        claim.status = "rejected"
        flash("Admin rejected ❌", "danger")

    db.session.commit()
    return redirect(url_for("admin_claims"))


# ---------------- RETURN CONFIRMATION ----------------
@app.route("/return/status/<int:claim_id>")
@login_required
def return_status(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    if current_user.id not in [claim.finder_id, claim.claimer_id]:
        flash("Access denied ❌", "danger")
        return redirect(url_for("home"))

    log = ReturnLog.query.filter_by(claim_id=claim.id).first()
    return render_template("return_status.html", claim=claim, log=log)


@app.route("/return/finder/<int:claim_id>")
@login_required
def return_finder(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    if claim.finder_id != current_user.id:
        flash("Access denied ❌", "danger")
        return redirect(url_for("home"))

    if claim.status != "finder_approved":
        flash("Only approved claims can be returned ✅", "warning")
        return redirect(url_for("finder_claims"))

    log = ReturnLog.query.filter_by(claim_id=claim.id).first()
    if not log:
        log = ReturnLog(claim_id=claim.id)
        db.session.add(log)

    log.finder_confirmed = True
    db.session.commit()

    flash("Finder confirmed return ✅ Waiting for owner confirmation.", "success")
    return redirect(url_for("return_status", claim_id=claim.id))


@app.route("/return/claimer/<int:claim_id>")
@login_required
def return_claimer(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    if claim.claimer_id != current_user.id:
        flash("Access denied ❌", "danger")
        return redirect(url_for("home"))

    log = ReturnLog.query.filter_by(claim_id=claim.id).first()
    if not log or not log.finder_confirmed:
        flash("Finder has not confirmed return yet ✅", "warning")
        return redirect(url_for("return_status", claim_id=claim.id))

    log.claimer_confirmed = True

    if log.finder_confirmed and log.claimer_confirmed:
        log.returned_at = datetime.utcnow()
        claim.status = "returned"
        claim.item.status = "returned"

        finder_user = User.query.get(claim.finder_id)
        if finder_user:
            finder_user.points += 10

    db.session.commit()

    flash("Owner confirmed received ✅ Case closed 🎉", "success")
    return redirect(url_for("return_status", claim_id=claim.id))


# ---------------- CHAT ----------------
@app.route("/chat/<int:claim_id>", methods=["GET", "POST"])
@login_required
def chat(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    if current_user.id not in [claim.finder_id, claim.claimer_id]:
        flash("Access denied ❌", "danger")
        return redirect(url_for("home"))

    if claim.status == "rejected":
        flash("Chat disabled ❌ This claim was rejected.", "warning")
        return redirect(url_for("my_claims"))

    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if text:
            msg = ChatMessage(claim_id=claim.id, sender_id=current_user.id, text=text)
            db.session.add(msg)
            db.session.commit()
        return redirect(url_for("chat", claim_id=claim.id))

    messages = ChatMessage.query.filter_by(claim_id=claim.id).order_by(ChatMessage.created_at.asc()).all()
    return render_template("chat.html", claim=claim, messages=messages)


# ---------------- REPORT SPAM ----------------
@app.route("/report-item/<int:item_id>", methods=["GET", "POST"])
@login_required
def report_item(item_id):
    item = Item.query.get_or_404(item_id)

    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        if not reason:
            flash("Please select a reason ✅", "warning")
            return redirect(url_for("report_item", item_id=item.id))

        rep = Report(item_id=item.id, reporter_id=current_user.id, reason=reason)
        db.session.add(rep)
        db.session.commit()

        flash("Reported successfully 🚩 Admin will review.", "success")
        return redirect(url_for("item_detail", item_id=item.id))

    return render_template("report_item.html", item=item)


# ---------------- ADMIN REPORTS ----------------
@app.route("/admin/reports")
@admin_required
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("admin_reports.html", reports=reports)


@app.route("/admin/archive-item/<int:item_id>")
@admin_required
def admin_archive_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.status = "archived"
    db.session.commit()
    flash("Item archived ✅", "success")
    return redirect(url_for("admin_reports"))


@app.route("/admin/delete-item/<int:item_id>")
@admin_required
def admin_delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    Claim.query.filter_by(item_id=item.id).delete()
    Report.query.filter_by(item_id=item.id).delete()
    db.session.delete(item)
    db.session.commit()

    flash("Item deleted permanently ✅", "danger")
    return redirect(url_for("admin_reports"))


# ---------------- ADMIN USERS ----------------
@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/make-admin/<int:user_id>")
@admin_required
def make_admin(user_id):
    if current_user.id == user_id:
        flash("You cannot change your own role ❌", "warning")
        return redirect(url_for("admin_users"))

    u = User.query.get_or_404(user_id)
    u.role = "admin"
    db.session.commit()
    flash("User is now Admin ✅", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/remove-admin/<int:user_id>")
@admin_required
def remove_admin(user_id):
    if current_user.id == user_id:
        flash("You cannot change your own role ❌", "warning")
        return redirect(url_for("admin_users"))

    u = User.query.get_or_404(user_id)
    u.role = "user"
    db.session.commit()
    flash("Admin role removed ✅", "success")
    return redirect(url_for("admin_users"))


# ---------------- ARCHIVED PAGE ----------------
@app.route("/archived")
@admin_required
def archived_posts():
    items = Item.query.filter_by(status="archived").order_by(Item.created_at.desc()).all()
    return render_template("archived.html", items=items)


# ---------------- MY POSTS / CLOSE / DELETE ----------------
@app.route("/my-posts")
@login_required
def my_posts():
    open_items = Item.query.filter_by(user_id=current_user.id, status="open").order_by(Item.created_at.desc()).all()
    closed_items = Item.query.filter(Item.user_id == current_user.id, Item.status != "open").order_by(Item.created_at.desc()).all()
    return render_template("my_posts.html", open_items=open_items, closed_items=closed_items)


@app.route("/close-item/<int:item_id>")
@login_required
def close_item(item_id):
    item = Item.query.get_or_404(item_id)

    if item.user_id != current_user.id:
        flash("You can't close someone else's post ❌", "danger")
        return redirect(url_for("item_detail", item_id=item.id))

    if item.status != "open":
        flash("This post is already closed ✅", "info")
        return redirect(url_for("item_detail", item_id=item.id))

    item.status = "returned"
    db.session.commit()

    flash("Post closed successfully ✅", "success")
    return redirect(url_for("my_posts"))


@app.route("/delete-item/<int:item_id>")
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    if item.user_id != current_user.id:
        flash("You can't delete someone else's post ❌", "danger")
        return redirect(url_for("item_detail", item_id=item.id))

    if Claim.query.filter_by(item_id=item.id).count() > 0:
        flash("Cannot delete ❌ This post already has claims.", "warning")
        return redirect(url_for("my_posts"))

    db.session.delete(item)
    db.session.commit()

    flash("Post deleted successfully ✅", "success")
    return redirect(url_for("my_posts"))


# ---------------- LEADERBOARD ----------------
@app.route("/leaderboard")
def leaderboard():
    users = User.query.order_by(User.points.desc()).limit(50).all()
    return render_template("leaderboard.html", users=users)


# ---------------- RUN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
