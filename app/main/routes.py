from flask import render_template, url_for, g, flash
from flask_babel import get_locale
from app import db
from app.main import bp
from app.main import quotes
from random import randint

@bp.route('/', methods=['GET', 'POST'])
@bp.route('/index', methods=['GET', 'POST'])
def index():
    print(len(quotes.quotes))
    return render_template('index.html', quote=quotes.quotes[randint(1, len(quotes.quotes))])

@bp.before_request
def before_request():
    # if current_user.is_authenticated:
    #     current_user.last_seen = datetime.utcnow()
    #     db.session.commit()
    #     g.search_form = SearchForm()
        # Get language code
    g.locale = str(get_locale())