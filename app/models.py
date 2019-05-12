from app import db, login
from datetime import datetime, timedelta
from time import time
import jwt
import json
import base64
import os
from flask import current_app, url_for
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5
from app.search import add_to_index, remove_from_index, query_index


class PaginatedAPIMixin(object):
    @staticmethod
    def to_collection_dict(query, page, per_page, endpoint, **kwargs):
        resources = query.paginate(page, per_page, False)
        data = {
            'items': [item.to_dict() for item in resources.items],
            '_meta': {
                'page': page,
                'per_page': per_page,
                'total_pages': resources.pages,
                'total_items': resources.total
            },
            '_links': {
                'self': url_for(endpoint, page=page, per_page=per_page, **kwargs),
                'next': url_for(endpoint, page=page + 1, per_page=per_page,
                                **kwargs) if resources.has_next else None,
                'prev': url_for(endpoint, page=page - 1, per_page=per_page,
                                **kwargs) if resources.has_prev else None
            }
        }
        return data


class User(PaginatedAPIMixin, UserMixin, db.Model):
    # __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    has_team = db.Column(db.Boolean, index=True, default=False)
    is_creator = db.Column(db.Boolean, index=True, default=False)
    is_admin = db.Column(db.Boolean, index=True, default=False)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(300))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    pomodoro_time = db.Column(db.Integer, default=25)
    short_break_time = db.Column(db.Integer, default=5)
    long_break_time = db.Column(db.Integer, default=20)
    # 0: offline, 1: online, 2: working, 3: resting
    online_state = db.Column(db.Integer, default=0)
    privacy = db.Column(db.Boolean, default=False)

    # Messages user implementation
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id',
                                    backref='author', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id',
                                        backref='recipient', lazy='dynamic')
    last_message_read_time = db.Column(db.DateTime)

    # Tasks
    tasks = db.relationship('Task', backref='user', lazy='dynamic')

    # Pomodoros
    pomodoros = db.relationship('Pomodoros', backref='user', lazy='dynamic')

    # Notifications
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')

    # API token implementation
    token = db.Column(db.String(32), index=True, unique=True)
    token_expiration = db.Column(db.DateTime)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=retro&s={}'.format(
            digest, size)

    def team_posts(self):
        if self.has_team:
            team_mates = User.query.filter_by(team_id=self.team_id).all()
            team_posts = Post.query.filter(Post.user_id.in_(team_mates))
            return team_posts.order_by(Post.timestamp.desc())
        else:
            return None
        
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({'reset_password': self.id, 'exp': time() + expires_in},
                          current_app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod  # It can be invoked directly from the class
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def new_messages(self):
        last_read_time = self.last_message_read_time or datetime(1900, 1, 1)
        return Message.query.filter_by(recipient=self).filter(Message.timestamp > last_read_time).count()

    def add_notification(self, name, data):
        # If a notification with the same name already exists, it is removed first
        self.notifications.filter_by(name=name).delete()
        n = Notification(name=name, payload_json=json.dumps(data), user=self)
        db.session.add(n)
        return n

    def to_dict(self, include_email=False): #TODO
        data = {
            'id': self.id,
            'username': self.username,
            'team_id': self.team_id,
            'last_seen': self.last_seen.isoformat() + 'Z',
            'about_me': self.about_me,
            'post_count': self.posts.count(),
            '_links': {
                'self': url_for('api.get_user', id=self.id),
                'avatar': self.avatar(128)
            }
        }
        if include_email:
            data['email'] = self.email
        return data

    def from_dict(self, data, new_user=False):
        for field in ['username', 'email', 'about_me']:
            if field in data:
                setattr(self, field, data[field])
        if new_user and 'password' in data:
            self.set_password(data['password'])

    def get_token(self, expires_in=3600):
        now = datetime.utcnow()
        if self.token and self.token_expiration > now + timedelta(seconds=60):
            return self.token
        self.token = base64.b64encode(os.urandom(24)).decode('utf-8')
        self.token_expiration = now + timedelta(seconds=expires_in)
        db.session.add(self)
        return self.token

    def revoke_token(self):
        self.token_expiration = datetime.utcnow() - timedelta(seconds=1)

    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_expiration < datetime.utcnow():
            return None
        return user


class Team(PaginatedAPIMixin, db.Model):
    # __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, index=True)
    teamname = db.Column(db.String(64), index=True, unique=True)
    about_team = db.Column(db.String(300))
    members = db.relationship('User', backref='team', lazy='dynamic')

    # API token implementation
    token = db.Column(db.String(32), index=True, unique=True)
    token_expiration = db.Column(db.DateTime)

    def __repr__(self):
        return '<Team {}>'.format(self.teamname)

    staticmethod
    def get_members(self):
        return [m for m in self.members]

    staticmethod
    def get_admins(self):
        return [m for m in self.members if m.is_admin == True]

    staticmethod
    def get_creator(self):
        return [m for m in self.members if m.is_creator == True][0]

    def get_invitation_token(self, expires_in=432000):
        return jwt.encode({'invitation_to_team': self.id, 'exp': time() + expires_in},
                          current_app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod  # It can be invoked directly from the class
    def verify_invitation_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])['invitation_to_team']
        except:
            return
        return Team.query.get(id)

    def get_token(self, expires_in=3600):
        now = datetime.utcnow()
        if self.token and self.token_expiration > now + timedelta(seconds=60):
            return self.token
        self.token = base64.b64encode(os.urandom(24)).decode('utf-8')
        self.token_expiration = now + timedelta(seconds=expires_in)
        db.session.add(self)
        return self.token

    def revoke_token(self):
        self.token_expiration = datetime.utcnow() - timedelta(seconds=1)

    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_expiration < datetime.utcnow():
            return None
        return user


class SearchableMixin(object):
    # A class method is a special method that is associated with the class and not a particular instance
    @classmethod
    # cls means that this method receives a class and not an instance as its first argument, instead of self
    def search(cls, expression, page, per_page):
        ids, total = query_index(cls.__tablename__, expression, page, per_page)
        if total == 0:
            return cls.query.filter_by(id=0), 0
        when = []
        for i in range(len(ids)):
            when.append((ids[i], i))
        return cls.query.filter(cls.id.in_(ids)).order_by(db.case(when, value=cls.id)), total
        # CASE statement from the SQL language, which needs to be used to ensure that the results from
        # the database come in the same order as the IDs are given. This is important because the
        # Elasticsearch query returns results sorted from more to less relevant.

    @classmethod
    def before_commit(cls, session):
        # These objects are not going to be available anymore after the session is committed,
        # so I need to save them before the commit takes place.
        session._changes = {
            'add': list(session.new),
            'update': list(session.dirty),
            'delete': list(session.deleted)
        }

    @classmethod
    def after_commit(cls, session):
        for obj in session._changes['add']:
            if isinstance(obj, SearchableMixin):
                add_to_index(obj.__tablename__, obj)
        for obj in session._changes['update']:
            if isinstance(obj, SearchableMixin):
                add_to_index(obj.__tablename__, obj)
        for obj in session._changes['delete']:
            if isinstance(obj, SearchableMixin):
                remove_from_index(obj.__tablename__, obj)
        session._changes = None

    @classmethod
    def reindex(cls):
        for obj in cls.query:
            add_to_index(cls.__tablename__, obj)


db.event.listen(db.session, 'before_commit', SearchableMixin.before_commit)
db.event.listen(db.session, 'after_commit', SearchableMixin.after_commit)


class Post(SearchableMixin, db.Model):
    __searchable__ = ['body']
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(5))

    def __repr__(self):
        return '<Post {}>'.format(self.body)


class Message(SearchableMixin, db.Model):
    __searchable__ = ['body']
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    language = db.Column(db.String(5))

    def __repr__(self):
        return '<Message {}>'.format(self.body)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.Float, index=True, default=time)
    payload_json = db.Column(db.Text)

    def get_data(self):
        return json.loads(str(self.payload_json))


class Task(SearchableMixin, db.Model):
    __searchable__ = ['body']
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    body = db.Column(db.String(500))
    state = db.Column(db.Boolean, index=True, default=True)


class Pomodoros(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    amount = db.Column(db.Integer, index=True, default=0)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
