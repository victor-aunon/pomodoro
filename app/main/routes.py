from datetime import datetime
from collections import OrderedDict
from random import randint
from textblob import TextBlob
from flask import render_template, url_for, g, flash, redirect, current_app
from flask_login import current_user, login_required
from flask_babel import get_locale, _, lazy_gettext as _l
from flask_paginate import Pagination
from app import db
from app.main import bp
from app.main import quotes
from app.main.forms import EditProfileForm, PostForm, SearchForm, MessageForm
from app.translate import translate
from app.models import User, Post, Message, Notification, Task, Pomodoros


@bp.route('/', methods=['GET', 'POST'])
@bp.route('/index', methods=['GET', 'POST'])
def index():
    return render_template('index.html', quote=quotes.quotes[randint(1, len(quotes.quotes))])

@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        g.search_form = SearchForm()
        # Get language code
    g.locale = str(get_locale())