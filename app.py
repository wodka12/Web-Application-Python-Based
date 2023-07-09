from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from forms import ProductForm
import configparser

pymysql.install_as_MySQLdb()

# DB config
config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{config.get('MYSQL','USER')}:{config.get('MYSQL','PASSWORD')}@{config.get('MYSQL','HOST')}/users"
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def check_password(self, password):
        return check_password_hash(self.password, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('Delete Account')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Integer, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin = db.relationship('User', backref=db.backref('products', lazy=True))

@app.route("/")
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route("/delete_account", methods=['GET', 'POST'])
@login_required
def delete_account():
    form = DeleteAccountForm()
    if form.validate_on_submit():
        # Delete the user account and log out
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Your account has been deleted!', 'success')
        return redirect(url_for('home'))
    return render_template('delete_account.html', title='Delete Account', form=form)

@app.route("/faq")
def faq():
    return render_template('faq.html', title='FAQ')

@app.route("/admin")
@login_required
def admin():
    if current_user.is_admin:
        products = Product.query.filter_by(admin_id=current_user.id).all()
        return render_template('admin.html', title='Admin Panel', products=products)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

@app.route("/add_product", methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            price=form.price.data,
            description=form.description.data,
            admin_id=current_user.id
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_product.html', title='Add Product', form=form)

@app.route("/edit_product/<int:product_id>", methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.admin_id == current_user.id:
        form = ProductForm()
        if form.validate_on_submit():
            product.name = form.name.data
            product.price = form.price.data
            product.description = form.description.data
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('admin'))
        elif request.method == 'GET':
            form.name.data = product.name
            form.price.data = product.price
            form.description.data = product.description
        return render_template('edit_product.html', title='Edit Product', form=form)
    else:
        flash('You do not have permission to edit this product.', 'danger')
        return redirect(url_for('admin'))

@app.route("/delete_product/<int:product_id>", methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.admin_id == current_user.id:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    else:
        flash('You do not have permission to delete this product.', 'danger')
    return redirect(url_for('admin'))

if __name__ == "__main__":
    app.run(debug=True)

