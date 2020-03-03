from flask import Flask, redirect, url_for, render_template, request
from flask import flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, BigInteger, String, DateTime
from sqlalchemy.sql import func, text
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_login import UserMixin, LoginManager,login_required
from flask_login import current_user, login_user, logout_user
from datetime import datetime, timedelta
from hashlib import md5
from base64 import b32encode


css = 'https://cdn.jsdelivr.net/npm/bulma@0.8.0/css/bulma.min.css'
expiry_time = timedelta(seconds=60)


app = Flask(__name__)
db_uri = 'postgresql://postgres:admin@127.0.0.1/urlshortener'
app.config['SECRET_KEY'] = 'alma-project'
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = Column(BigInteger, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(100))
    name = Column(String(100))


class Url(db.Model):
    __tablename__ = 'urls'
    hash = Column(String(50), primary_key=True)
    full_url = Column(String(2000))
    user_id = Column(BigInteger)
    visits_safari = Column(Integer, server_default=text('0'))
    visits_chrome = Column(Integer, server_default=text('0'))
    visits_firefox = Column(Integer, server_default=text('0'))
    visits_edge = Column(Integer, server_default=text('0'))
    visits_other = Column(Integer, server_default=text('0'))
    created = Column(DateTime, server_default=func.now())

    @property
    def visits_all(self):
        total = 0
        total += self.visits_safari
        total += self.visits_chrome
        total += self.visits_firefox
        total += self.visits_edge
        total += self.visits_other
        return total


def expiry_cleanup(user_id=None, hash=None, limit=None):
    date_limit = datetime.now() - expiry_time
    query = Url.query
    if hash:
        query = query.filter_by(hash=hash)
    if user_id:
        query = query.filter_by(user_id=user_id)
    query = query.filter(Url.created <= date_limit)
    if limit:
        query = query.order_by(Url.created).limit(limit)
    for x in query:
        db.session.delete(x)
    db.session.commit()

    
@app.cli.command('db_create')
def db_create():
    db.create_all()
    print('Database created!')


@app.cli.command('db_drop')
def db_drop():
    db.drop_all()
    print('Database dropped!')


@app.cli.command('db_cleanup')
def db_cleanup():
    expiry_cleanup()
    print('Expired short URLS removed.')
    

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html',
                               css=css,
                               user=current_user)
    
    return render_template('login.html',
                           css=css,
                           user=current_user)


@app.route('/<hash>')
def get_url(hash):
    user_browser = request.user_agent.browser
    expiry_cleanup(hash=hash)
    
    for x in Url.query.filter_by(hash=hash):
        if user_browser == 'safari':
            x.visits_safari += 1
        elif user_browser == 'chrome':
            x.visits_chrome += 1
        elif user_browser == 'firefox':
            x.visits_firefox += 1
        elif user_browser == 'edge':
            x.visits_edge += 1
        else:
            x.visits_other += 1
        db.session.commit()
        return redirect(x.full_url), 301
    
    return render_template('404.html',
                           css=css,
                           user=current_user), 404


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id
    expiry_cleanup(user_id=user_id)
    
    urls_list = [ { 'hash': x.hash,
                    'full_url': x.full_url,
                    'expiry_date': x.created + expiry_time,
                    'visits_safari': x.visits_safari,
                    'visits_chrome': x.visits_chrome,
                    'visits_firefox': x.visits_firefox,
                    'visits_edge': x.visits_edge,
                    'visits_other': x.visits_other,
                    'visits_all': x.visits_all }
                  for x in Url.query.filter_by(user_id=user_id) ]

    return render_template('dashboard.html',
                           css=css,
                           user=current_user,
                           urls_list=urls_list)


@app.route('/shorten', methods=['POST'])
def shorten():
        full_url = request.form.get('full_url')
        user_id = current_user.id
        expiry_cleanup(limit=1)
        
        while True:
            now = datetime.now()
            full = full_url + str(user_id) + str(now)
            bfull = full.encode('utf-8')
            bhash = (md5(bfull).digest())[:5]
            hash = (b32encode(bhash).decode('utf-8').lower())[:7]

            expiry_cleanup(hash=hash)            

            url_entry = Url(hash=hash,
                            full_url=full_url,
                            user_id=user_id)

            looping = False
            try:
                db.session.add(url_entry)
                db.session.commit()
            except (IntegrityError):
                db.session.rollback()
                looping = True
            if not looping:
                break
        
        return redirect(url_for('dashboard'))

    
@app.route('/remove', methods=['POST'])
def remove():
        hash = request.form.get('hash')

        for x in Url.query.filter_by(hash=hash):
            db.session.delete(x)
        db.session.commit()
        
        return redirect(url_for('dashboard'))


@app.route('/login')
def login():
    return render_template('login.html',
                           css=css,
                           user=current_user)


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email').lower()
    password = request.form.get('password')

    login_success = False
    for x in User.query.filter_by(email=email):
        login_user(x)
        login_success = check_password_hash(x.password, password)

    if not login_success:
        flash('Please check your login details and try again.')
        return redirect(url_for('login'))

    return redirect(url_for('dashboard'))


@app.route('/signup')
def signup():
    return render_template('signup.html',
                           css=css,
                           user=current_user)


@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email').lower()
    name = request.form.get('name')
    password = request.form.get('password')
    hashed_password = generate_password_hash(password,
                                             method='sha256')

    if User.query.filter_by(email=email).first():
        flash('Email address already exists')
        return redirect(url_for('signup'))
    
    new_user = User(email=email,
                    name=name,
                    password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
