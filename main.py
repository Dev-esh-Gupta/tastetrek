from flask import Flask, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length, EqualTo, Regexp
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date


class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    login = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name')
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    mobile = StringField('Contact Number', validators=[DataRequired(), Length(min=10, max=10), Regexp(regex='^[6-9]{1}[0-9]{9}$')])
    password = PasswordField('Enter Password', validators=[DataRequired(), Length(min=6, max=15)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6, max=15), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'tastetrekprivatelimited'
Bootstrap5(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tastetrek.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


# Create User_Loader Callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Customer, user_id)


# CONFIGURE TABLE
class Customer(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    mobile: Mapped[str] = mapped_column(String(15), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=True)


class Menu(db.Model):
    item_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    price: Mapped[int] = mapped_column(Integer, nullable=False)
    offer_price: Mapped[int] = mapped_column(Integer, nullable=False)
    item_url: Mapped[str] = mapped_column(String(500), nullable=False)



with app.app_context():
    db.create_all()


@app.route('/', methods=['GET', 'POST'])
def home():
    # TODO: Query the database for all the posts. Convert the data to a python list.
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        # find customer by email address
        result = db.session.execute(db.select(Customer).where(Customer.email == email))
        user = result.scalar()

        if not user:
            flash('That email does not exist, please try again.')
            return redirect(url_for('home'))
        elif not check_password_hash(user.password, password):
            flash('Password Incorrect, please try again')
        else:
            login_user(user)
            return redirect(url_for('dashboard'))

        # Find user by email address

    return render_template("index.html", form=login_form, logged_in = current_user.is_authenticated)


# TODO: Add a route so that you can click on individual posts.
@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegistrationForm()
    if register_form.validate_on_submit():
        email=register_form.email.data
        result=db.session.execute(db.select(Customer).where(Customer.email == email))
        user = result.scalar()
        if user:
            flash('This email is already register with us, Login instead!')
            return redirect(url_for('register'))

        hash_salted_password = generate_password_hash(
            register_form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = Customer(
            name=f'{register_form.first_name.data} {register_form.last_name.data}',
            email=register_form.email.data,
            mobile=register_form.mobile.data,
            password=hash_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template("registration.html", form=register_form, logged_in = current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    result = db.session.execute(db.select(Menu))
    menu_items = result.scalars().all()
    return render_template('dashboard.html', items=menu_items, logged_in = True)


@app.route('/cart')
def cart():
    return render_template('cart.html')



# Below is the code from previous lessons. No changes needed.
@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5005)
