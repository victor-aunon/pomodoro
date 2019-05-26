from datetime import datetime, timedelta
from collections import OrderedDict
from random import randint
from textblob import TextBlob
from sqlalchemy import and_
from flask import render_template, url_for, g, flash, redirect, current_app, request, jsonify
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


@bp.route('/add-task', methods=['POST'])
@login_required
def add_task():
    task = Task(user_id=current_user.id, timestamp=datetime.utcnow(),
                body=request.form['body'], state=True)
    db.session.add(task)
    db.session.commit()
    return jsonify({'status': 'Active'})


@bp.route('/complete-task', methods=['POST'])
@login_required
def complete_task():
    task = Task.query.filter(and_(Task.user_id == current_user.id, Task.body == request.form['body'], Task.state == True)).first()
    if task is None:
        return render_template('index.html', quote=quotes.quotes[randint(1, len(quotes.quotes))])
    else:
        task.state=False
        db.session.add(task)
        db.session.commit()
        return jsonify({'status': 'Completed'})


@bp.route('/get-tasks')
@login_required
def get_tasks():
    active_tasks = Task.query.filter(and_(Task.user_id == current_user.id, Task.state == True)).order_by(Task.timestamp.desc())
    incompleted_tasks_today = Task.query.filter(and_(Task.user_id == current_user.id, Task.state == False,
                            Task.timestamp >= datetime.utcnow() - timedelta(hours=12))).order_by(Task.timestamp.desc())
    tasks = active_tasks.all() + incompleted_tasks_today.all()
    return jsonify([{'body': t.body, 'state': t.state} for t in tasks])


# @bp.route('/user/<username>')
# @login_required
# def user(username):
#     user = User.query.filter_by(username=username).first_or_404()
#     page = request.args.get('page', 1, type=int)
#     settings = None
#     if user.id == current_user.id:
#         settings = [user.pomodoro_time, user.short_break_time,
#                     user.long_break_time, user.privacy]
    # per_page = current_app.config['POSTS_PER_PAGE']
    # posts = user.posts.order_by(Post.timestamp.desc()).paginate(
    #     page, per_page, False)
    # if page == 1:
    #     first_this_page = 1
    #     last_this_page = len(posts.items)
    # else:
    #     first_this_page = ((page - 1) * per_page) + 1
    #     last_this_page = first_this_page + len(posts.items) - 1
    # pagination = Pagination(page=page, total=posts.total, search=False, per_page=per_page, bs_version=4,
    #                 display_msg=_('displaying %(first_this_page)d - %(last_this_page)d records of %(total)d', 
    #                                first_this_page=first_this_page, last_this_page=last_this_page,
    #                                total=posts.total))
#     return render_template('user.html',  title='{}'.format(username),
#                             user=user, posts=posts.items, pagination=pagination)


@bp.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        g.search_form = SearchForm()
        # Get language code
    g.locale = str(get_locale())