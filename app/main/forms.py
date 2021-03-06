from flask_wtf import FlaskForm
from flask import request
from wtforms import Form
from wtforms.fields.html5 import IntegerRangeField
from wtforms import StringField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, ValidationError, Length, NumberRange
from app.models import User
from flask_babel import _, lazy_gettext as _l


class EditProfileForm(FlaskForm, Form):
    username = StringField(_l('Username'), validators=[DataRequired()])
    about_me = TextAreaField(_l('About me'), validators=[Length(min=0, max=300)])
    pomodoro = IntegerRangeField(_l('Pomodoro duration'),
                        validators=[NumberRange(min=20, max=30)])
    short_break = IntegerRangeField(_l('Short break duration'),
                        validators=[NumberRange(min=5, max=10)])
    long_break = IntegerRangeField(_l('Long break duration'),
                        validators=[NumberRange(min=15, max=30)])
    privacy = BooleanField(_l('Show my online state'), default="checked")
    submit = SubmitField(_l('Submit'))

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError(_l('Please use a different username.'))


class PostForm(FlaskForm):
    post = TextAreaField(_l('Say something'), validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField(_l('Submit'))


class SearchForm(FlaskForm):
    q = StringField(_l('Search'), validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        if 'formdata' not in kwargs:
            # The default is to use request.form, which is where Flask puts form values
            # that are submitted via POST request. Forms that are submitted via GET
            # request get have the field values in the query string
            kwargs['formdata'] = request.args
        if 'csrf_enabled' not in kwargs:
            # For clickable search links to work, CSRF needs to be disabled
            kwargs['csrf_enabled'] = False
        super(SearchForm, self).__init__(*args, **kwargs)


class MessageForm(FlaskForm):
    message = TextAreaField(_l('Message'), validators=[DataRequired(), Length(min=0, max=1000)])
    submit = SubmitField(_l('Submit'))


