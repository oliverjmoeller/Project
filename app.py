from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps

import pymysql
import secrets
import os

dbuser = os.environ.get('DBUSER')
dbpass = os.environ.get('DBPASS')
dbhost = os.environ.get('DBHOST')
dbname = os.environ.get('DBNAME')


#conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(secrets.dbuser, secrets.dbpass, secrets.dbhost, secrets.dbname)
conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(dbuser, dbpass, dbhost, dbname)
# Open database connection
#dbhost = secrets.dbhost
#dbuser = secrets.dbuser
#dbpass = secrets.dbpass
#dbname = secrets.dbname

#db = pymysql.connect(dbhost, dbuser, dbpass, dbname)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SuperSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = conn
#db = SQLAlchemy(app)

login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger' # sets flash category for the default message 'Please log in to access this page.'


app.config['SECRET_KEY']='SuperSecretKey'
# import os
# = os.environ.get('SECRET_KEY')


# Prevent --> pymysql.err.OperationalError) (2006, "MySQL server has gone away (BrokenPipeError(32, 'Broken pipe')
class SQLAlchemy(_BaseSQLAlchemy):
     def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
# <-- MWC


app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')

class AccountDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])


ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

class User(UserMixin, db.Model):
    __tablename__ = 'omoeller_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)

    def __init__(self, name, email, username, access=ACCESS['guest']):
        self.id = ''
        self.name = name
        self.email = email
        self.username = username
        self.password_hash = ''
        self.access = access

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)

class omoeller_matches(db.Model):
    match_no = db.Column(db.Integer, primary_key=True)
    player_name_01 = db.Column(db.String(100))
    player_name_02 = db.Column(db.String(100))
    player_name_03 = db.Column(db.String(100))
    player_name_04 = db.Column(db.String(100))
    player_score_01 = db.Column(db.Integer)
    player_score_02 = db.Column(db.Integer)
    player_score_03 = db.Column(db.Integer)
    player_score_04 = db.Column(db.Integer) 

class matchForm(FlaskForm):
    match_no = IntegerField('Match No:')
    player_name_01 = StringField('Player 01 Name:', validators=[DataRequired()])
    player_name_02 = StringField('Player 02 Name:', validators=[DataRequired()])
    player_name_03 = StringField('Player 03 Name:')
    player_name_04 = StringField('Player 04 Name:')
    player_score_01 = IntegerField('Player 01 Score:', validators=[DataRequired()])
    player_score_02 = IntegerField('Player 02 Score:', validators=[DataRequired()])
    player_score_03 = IntegerField('Player 03 Score:')
    player_score_04 = IntegerField('Player 03 Score:')




@login.user_loader
def load_user(id):
    return User.query.get(int(id))  #if this changes to a string, remove int


### custom wrap to determine access level ###
def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: #the user is not logged in
                return redirect(url_for('login'))

            #user = User.query.filter_by(id=current_user.id).first()

            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator




#### Routes ####

# index
@app.route('/')
@app.route('/index')
def index():
    
    return render_template('index.html', pageTitle='Smash App')



# registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  pageTitle='Register', form=form)

# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html',  pageTitle='Login', form=form)


#logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


################ GUEST ACCESS FUNCTIONALITY OR GREATER ###################

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.get_or_404(current_user.id)
    form = AccountDetailForm()

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.set_password(form.password.data)

        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('account'))

    form.name.data = user.name
    form.email.data = user.email

    return render_template('account_detail.html', form=form, pageTitle='Your Account')






################ ADMIN ACCESS FUNCTIONALITY ###################

# control panel
@app.route('/control_panel')
@requires_access_level(ACCESS['admin'])
def control_panel():
    all_users = User.query.all()
    return render_template('control_panel.html', users=all_users, pageTitle='Control Panel')

# user details & update
@app.route('/user_detail/<int:user_id>', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.access.data = user.access
    return render_template('user_detail.html', form=form, pageTitle='User Details')

# update user
@app.route('/update_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    orig_user = user.username # get user details stored in the database - save username into a variable

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != orig_user: # if the form data is not the same as the original username
            valid_user = User.query.filter_by(username=new_user).first() # query the database for the usernam
            if valid_user is not None:
                flash("That username is already taken...", 'danger')
                return redirect(url_for('control_panel'))

        # if the values are the same, we can move on.
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    if request.method == 'POST': #if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# new user
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user.html',  pageTitle='New User | My Flask App', form=form)

# add Match
@app.route('/add_match', methods=['GET','POST'])
@requires_access_level(ACCESS['user'])
def add_match():
    form = matchForm()
    if form.validate_on_submit():
        match = omoeller_matches(player_name_01 = form.player_name_01.data, player_name_02 = form.player_name_02.data, player_name_03 = form.player_name_03.data, player_name_04 = form.player_name_04.data, player_score_01 = form.player_score_01.data, player_score_02 = form.player_score_02.data, player_score_03 = form.player_score_03.data,player_score_04 = form.player_score_04.data)
        db.session.add(match)
        db.session.commit()
        #return "<h2> New match added to database, containing players: {0}, {1}, {2}, {3} and scores: {4},{5},{6},{7} respectively".format(form.player_name_01.data, form.player_name_02.data, form.player_name_03.data, form.player_name_04.data, form.player_score_01.data, form.player_score_02.data, form.player_score_03.data, form.player_score_04.data)
        flash('You have successfully added match.', 'success')
        return redirect("/match_record")
    return render_template('add_match.html', form=form, pageTitle='Add NEW Match Info')

# Match record 
@app.route('/match_record')
def match_record():
    all_matches = omoeller_matches.query.all()
    return render_template('match_record.html', matches = all_matches, pageTitle ="Match Records")

@app.route('/match_edit')
@requires_access_level(ACCESS['admin'])
def match_edit():
    all_matches2 = omoeller_matches.query.all()
    return render_template('match_edit.html', matches = all_matches2, pageTitle ="Manage Match Records")

@app.route('/delete_match/<int:match_no>', methods=['GET', 'POST'])
def delete_match(match_no):
    if request.method == 'POST':
        match = omoeller_matches.query.get_or_404(match_no)
        db.session.delete(match)
        db.session.commit()
        return redirect("/match_edit")
    else:
        return redirect("/match_edit")

@app.route('/match/<int:match_no>', methods=['GET', 'POST'])
def get_match(match_no):
    match = omoeller_matches.query.get_or_404(match_no)
    return render_template('match.html', form = match, pageTitle='Match Details')

@app.route('/match/<int:match_no>/update', methods=['GET', 'POST'])
def update_match(match_no):
    match = omoeller_matches.query.get_or_404(match_no)
    form = matchForm()

    if form.validate_on_submit():
        match.player_name_01 = form.player_name_01.data
        match.player_name_02 = form.player_name_02.data
        match.player_name_03 = form.player_name_03.data
        match.player_name_04 = form.player_name_04.data
        match.player_score_01 = form.player_score_01.data
        match.player_score_02 = form.player_score_02.data
        match.player_score_03 = form.player_score_03.data
        match.player_score_04 = form.player_score_04.data
        db.session.commit()
        return redirect(url_for('get_match', match_no = match.match_no))
    form.match_no =match.match_no
    form.player_name_01.data = match.player_name_01
    form.player_name_02.data = match.player_name_02
    form.player_name_03.data = match.player_name_03
    form.player_name_04.data = match.player_name_04
    form.player_score_01.data = match.player_score_01
    form.player_score_02.data = match.player_score_02
    form.player_score_03.data = match.player_score_03
    form.player_score_04.data = match.player_score_04
    return render_template('update_match.html', form=form, pageTitle ='Update Match')

    



if __name__ == '__main__':
    app.run(debug=True)
