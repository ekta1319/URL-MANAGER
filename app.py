from operator import methodcaller, truediv
from flask import Flask, render_template,request,redirect, url_for,session,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_mail import Mail, Message
import random

app = Flask(__name__)
app.secret_key = 'DEV'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///url.db'


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ektac587@gmail.com'         # Your Gmail
app.config['MAIL_PASSWORD'] = 'luhxklvkzarlqilr'     # App Password from Step 2
app.config['MAIL_DEFAULT_SENDER'] = 'ektac587@gmail.com'   # Must match MAIL_USERNAME


mail = Mail(app)

db = SQLAlchemy(app)


class user(db.Model):
    Name = db.Column(db.String, primary_key=True)
    Category = db.Column(db.String(200), nullable=False)
    URL = db.Column(db.String, nullable=False)
    favorite = db.Column(db.Boolean, default=False, nullable=False)
    userId= db.Column(db.String, db.ForeignKey('user2.id'), nullable=True)
    
class user2(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200))
    users = db.relationship('user', backref='user', lazy=True)
    cred = db.relationship('credential', backref='credential', lazy=True)
 
class credential(db.Model):
    app_name = db.Column(db.String,nullable = False, primary_key=True)
    password = db.Column(db.String)
    userId= db.Column(db.String, db.ForeignKey('user2.id'))

    
    
with app.app_context():
    db.create_all()



@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    items = user.query.filter_by(userId=user_id).all()
    length = len(items)
    categories = [doc.Category for doc in user.query.with_entities(user.Category).filter_by(userId=user_id).distinct()]
    favorite = user.query.filter_by(userId=user_id, favorite=True).all()

    return render_template(
        'index.html',
        items=length,
        category=len(categories),
        favorite=len(favorite),
        user_name=session.get('user_name')
    )
   


@app.route('/url')
def url():
    return render_template("for_url.html")

@app.route('/login')
def loginpage():
    return render_template("login.html")

@app.route('/register')
def newuser():
    return render_template("register.html")


@app.route('/createUser', methods=["POST"])
def createUser():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        User2 = user2.query.filter_by( email=email).first()
        if User2:
            print("User already exist")
        
        newUser=user2(
            full_name=full_name,
            email=email, 
            password=password
        )
        db.session.add(newUser)
        db.session.commit()
        
        return redirect('/login')
    


@app.route("/login-user", methods=["POST"])
def loginUser():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        logged_in_user = user2.query.filter_by(email=email).first()

        if not logged_in_user:
            print('User not registered. Please register.')
            return redirect("/register")

        if logged_in_user.password == password:
            print("User successfully logged in")
            session['user_id'] = logged_in_user.id
            session['user_name'] = logged_in_user.full_name
            return redirect("/")
        else:
            print("Incorrect password")
            return redirect("/login")

            
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route('/view-all')
def view_all():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    all_users = user.query.filter_by(userId=user_id).all()
    return render_template("view_all.html", users=all_users)



@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        if 'user_id' not in session:
            return redirect('/login')  # Secure the route
        
        Name = request.form.get('Name')
        Category = request.form.get('Category')
        URL = request.form.get('URL')

        new_url = user(
            Name=Name,
            Category=Category,
            URL=URL,
            userId=session['user_id']  
        )
        db.session.add(new_url)
        db.session.commit()
        return redirect(url_for('home'))  

    
@app.route('/delete-card', methods=['POST'])
def delete_card():
    name = request.form.get("name")
    category = request.form.get("category")
    url = request.form.get("url")
 
    User = user.query.filter_by(Name=name, Category=category, URL=url).first()

    if User:
        db.session.delete(User)
        db.session.commit()
        return redirect('/view-all')
    else:
        return "User not found", 404



@app.route('/favorite', methods=['POST'])
def favorite():
    Name = request.form.get("name")
    Category = request.form.get("category")
    URL = request.form.get("url")

    User = user.query.filter_by(Name=Name, Category=Category, URL=URL).first()

    if User:
        User.favorite = True
        db.session.add(User)  
        db.session.commit()
        return redirect(url_for('home'))

@app.route('/unfavorite', methods=['POST'])
def unfavorite():
    Name = request.form.get("name")
    Category = request.form.get("category")
    URL = request.form.get("url")

    User = user.query.filter_by(Name=Name, Category=Category, URL=URL).first()

    if User:
        User.favorite = False
        db.session.add(User)  
        db.session.commit()
        return redirect(url_for('home'))


@app.route('/view-all-favorite')
def viewAllFavorite():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    favorites = user.query.filter_by(userId=user_id, favorite=True).all()
    return render_template("view-all-favourite.html", favorites=favorites)



@app.route('/all-credentials')
def all_credentials():
    return render_template("all_credentials.html")

@app.route('/add-credentials')
def add_credentials():
    return render_template("add_credentials.html")



@app.route("/verify-otp", methods=["POST"])
def verifyOTP():
    if request.method == "POST":
        entered_otp = request.form.get("otp")
        if entered_otp == session.get("otp"):
            flash("OTP Verified!", "success")
            return redirect("/view-all-info")
        else:
            flash("Invalid OTP", "danger")
            return redirect("/all-credentials")


@app.route("/view-all-info", methods=['GET'])
def allInfo():
    if "user_id" not in session:
       return  redirect("/login")
    user_id=session["user_id"]
    credientials=credential.query.filter_by(userId=user_id).all()
    print(credientials)
    return render_template("all_info.html", credentials=credientials)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp  
        session['email'] = email
        msg = Message('Your OTP Code', recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)
        return redirect("/otp-verify")
        
@app.route("/otp-verify", methods=["GET"])
def otpVerify():
    return render_template("verify.html")


@app.route('/add-crediential', methods=["POST"])
def creden():
    if request.method == 'POST':
        if 'user_id' not in session:
            return redirect('/login')
        user_id = session['user_id']
        app_name = request.form.get('app_name')
        password = request.form.get('password')
        
        newUser=credential(
            app_name=app_name,
            password=password,
            userId=user_id
            )
        db.session.add(newUser)
        db.session.commit()
        
        return redirect('/')
    
@app.route('/delete-credential', methods=['POST'])
def delete_credential():
    app_name = request.form.get('app_name')
    password = request.form.get('password')

    # Assuming app_name + password is unique for a user
    credential_to_delete = credential.query.filter_by(app_name=app_name, password=password).first()
    
    if credential_to_delete:
        db.session.delete(credential_to_delete)
        db.session.commit()
        flash("Credential deleted successfully.", "success")
    else:
        flash("Credential not found.", "danger")

    return redirect('/view-all-info')  # Or your actual credentials view




if __name__ == '__main__':
    app.run(debug=True)

