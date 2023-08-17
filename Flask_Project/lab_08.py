"""
@name Kevin Pineda
@class SDEV 300 6980
@date 08/03/2023
Lab 8

Python Web Page Code

Creates a unique web page using the flask framework
"""
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from forms import RegistrationForm, LoginForm, PasswordUpdateForm

app = Flask(__name__)

app.config['SECRET_KEY'] = 'iamamonkey123456789'

now = datetime.now()
formatted_now = now.strftime("%A, %d %B, %Y at %X")

schools = [
    {
        'name': 'University of Maryland - Global Campus',
        'title': 'Get Transcripts',
        'Fee': '$10 Fee Per School',
    },
    {
        'name': 'University of Utah',
        'title': 'Get Transcripts',
        'Fee': '$13 Fee Per School',
    },
    {
        'name': 'Salt Lake Community College',
        'title': 'Get Transcripts',
        'Fee': '$9 Fee Per School',
    }
]


@app.route('/')
@app.route("/home")
@login_required
def home():
    """
    Routes to the webpage using Flask framework. Will always route
    to root folder.Locked to only users that are valid.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'home.html' webpage

    """
    return render_template('home.html', schools=schools, curr_date=formatted_now)


@app.route("/memes")
@login_required
def memes():
    """
    Routes to the webpage using Flask framework. Locked to only users
    that are valid.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'memes.html' webpage

    """
    return render_template('memes.html', title=memes)


@app.route("/grades")
@login_required
def grades():
    """
    Routes to the webpage using Flask framework. Locked to only users
    that are valid.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'grades.html' webpage

    """
    return render_template('grades.html', title=grades)


@app.route("/date")
@login_required
def date():
    """
    Routes to the webpage using Flask framework. Provides the current
    date and time. Locked to only users that are valid.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'date.html' webpage

    """
    content = "It's " + formatted_now
    return render_template('date.html', content=content)


@app.route("/register", methods=['GET', 'POST'])
def register():
    """
    Routes to the webpage using Flask framework. Page for registration of
    a user. Checks if a users username or email exists in the database (.txt).
    Writes the new information to a new line in the database (.txt) to create
    a user.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'home.html' webpage

    """
    form = RegistrationForm()

    if form.validate_on_submit():

        # Reading user_data.txt for existing user
        with open("user_data.txt", "r", encoding="utf-8") as file:
            existing_users = file.readlines()

            # Checking all users
            for user in existing_users:
                user_data = user.strip().split(',')
                username, email, *_ = user_data

                # If the username or the email exist, give message and not allow registration
                if form.username.data == username or form.email.data == email:
                    flash("Username or Email Exists!")
                    return redirect(url_for('register'))

        # Writing to user_data.txt database new user information
        with open("user_data.txt", "a", encoding="utf-8") as file:
            file.write(f"{form.username.data},{form.email.data},"
                       f"{form.password.data}, 'No Secret'\n")
        flash(f'Account Created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    Routes to the webpage using Flask framework. Page for logging in to
    the website. Checks if the email and password match what is in the
    database (.txt). GIves a message for success and unsuccessful attempts.
    Logs any failed attempts if it is an existing user.


    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'login.html' webpage or redirects to home

    """
    form = LoginForm()

    is_failed_attempt = False

    failed_email = ''

    if form.validate_on_submit():

        # Opening the file to read
        with open("user_data.txt", "r", encoding="utf-8") as file:
            users = file.readlines()

            # Going through each user
            for user in users:
                user_data = user.strip().split(',')

                # Adding check if the length of the line is less than 4 items
                if len(user_data) != 4:
                    continue
                username, email, pwd, *_ = user_data

                # Checking if email and password match
                if form.email.data == email and form.password.data == pwd:
                    user = User(username, email, pwd)
                    login_user(user)
                    flash('You have been logged in!', 'success')
                    return redirect(url_for('home'))

                # If email matches but not password, we log this failed attempt
                if form.email.data == email and form.password.data != pwd:
                    is_failed_attempt = True
                    failed_email = email

            # If nothing is returned, an error message appears
            flash('Login Unsuccessful. Please check username and password', 'danger')

        # If a failed attempt of an email, we log the attempt
        if is_failed_attempt:
            ipaddress = request.remote_addr
            failed_date_time = now

            # Opening the logger.txt file to write the IP Address, date/time, and the email
            with open("logger.txt", "a", encoding="utf-8") as file:
                file.write(f"IP: {ipaddress}, Date & Time: {failed_date_time}, "
                           f"Email: {failed_email}\n")

    return render_template('login.html', title='Login', form=form)


@app.route("/password_update", methods=['GET', 'POST'])
@login_required
def password_update():
    """
    Routes to the password update webpage using Flask framework. Allows a user
    to update their password and associated secret if they provide a valid
    existing email and password combination. The function checks the existing
    records in the database (user_data.txt) and updates the password and secret
    if a match is found.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'password_update.html' webpage after an attempt. Redirects
        to the home page if the update is successful.

    """
    form = PasswordUpdateForm()

    if form.validate_on_submit():

        # Reading the users
        with open("user_data.txt", "r", encoding="utf-8") as file:
            users = file.readlines()

        updated = False

        # Iterating through the users, getting data
        for i, user in enumerate(users):
            username, email, pwd, *_ = user.strip().split(',')

            # If the inputted email and password exist, then replace the users data
            if form.email.data == email and form.password.data == pwd:
                users[i] = f"{username},{email},{form.new_password.data}," \
                           f"{form.password_secret.data}\n"
                updated = True
                break

        # If the update was successful, write the new information, give success message
        if updated:
            with open("user_data.txt", "w", encoding="utf-8") as file:
                file.writelines(users)
                flash('Password and secret have been updated!', 'success')
                return redirect(url_for('home'))
        else:
            flash('Update unsuccessful. Please check your old password.', 'danger')

    return render_template('password_update.html', title='Password Update', form=form)


@app.route("/logout")
@login_required
def logout():
    """
    Routes to the webpage using Flask framework. Logs out the current
    user in the website. Disallows access to @login_required routes.

    Parameters
    ----------
    N/A

    Returns
    -------
    render_template
        Returns the 'home.html' webpage

    """
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('home'))


# Sets up the login manger to use for logging in.
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    """
    Creates a User object to be used when creating a new user.

    Parameters
    ----------


    """

    def __init__(self, username, email, password):
        """
        Routes to the webpage using Flask framework. Will always route
        to root folder.

        Parameters
        ----------
        username

        email

        password

        """
        self.username = username
        self.email = email
        self.password = password

    def get_id(self):
        """
        Gets the ID as the users email.

        Parameters
        ----------
        self

        Returns
        -------
        email
            user's email

        """
        return self.email

    @login_manager.user_loader
    def load_user(self):
        """
        Gets the current users information and loads it as a main
        account.

        Parameters
        ----------
        N/A

        Returns
        -------
        User
            Object of a user
        """
        with open("user_data.txt", "r", encoding="utf-8") as file:
            users = file.readlines()
            for user in users:
                username, email, pwd = user.strip().split(',')[:3]
                if email == self:
                    return User(username, email, pwd)
        return None


if __name__ == "__main__":
    app.run(debug=True)
