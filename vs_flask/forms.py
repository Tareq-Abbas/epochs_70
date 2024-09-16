from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from video5 import User

class RegistrationForm(FlaskForm):
    fname= StringField('First Name', validators=[DataRequired(), Length(min=2, max=26)])
    lname= StringField('Last Name', validators=[DataRequired(), Length(min=2, max=26)])
    username= StringField('User Name', validators=[DataRequired(), Length(min=2, max=26)])
    email= StringField('Email', validators=[DataRequired(), Email()])
    #the password here does not accept (.)
    password= PasswordField('Password', validators=[DataRequired(), Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$")])
    confirm_password= PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit= SubmitField('Submit')

    def validate_username(self, username):
        user = User.query.filter_by(username= username.data).first()
        if user:
            raise ValidationError('Username already exists! please use another one.')
        
    def validate_email(self, email): 
        user = User.query.filter_by(email= email.data).first()
        if user:
            raise ValidationError('Email already exists! please use another one.')


class LoginForm(FlaskForm):
    email= StringField('Email', validators=[DataRequired(), Email()])
    password= PasswordField('Password', validators=[DataRequired()])
    remember= BooleanField('Remember Me')
    submit= SubmitField('Login')


