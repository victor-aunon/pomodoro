from flask import render_template, flash, redirect, url_for, request
from werkzeug.urls import url_parse
from flask_login import current_user, login_user, logout_user
from flask_babel import _
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationFormTeamCreator, ResetPasswordForm
from app.auth.forms import ResetPasswordRequestForm, RegistrationForm
from app.models import User, Team
from app.auth.email import send_password_reset_email


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'), category='danger')
            return redirect(url_for('auth.login'))
        login_user(user, remember=form.remember_me.data) # Here current_user is created
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title=_('Sign In'), form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    form_creator = RegistrationFormTeamCreator()
    if form.submit.data:
        creator = False
    elif form_creator.submit_creator.data:
        creator = True
    if form.submit.data and form.validate():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'), category='success')
        return redirect(url_for('auth.login'))
    if form_creator.submit_creator.data and form_creator.validate():
        team = Team(teamname=form_creator.teamname.data)
        db.session.add(team)
        user = User(username=form_creator.username.data, email=form_creator.email.data, team=team,
                    online_state=1)
        user.set_password(form_creator.password.data)
        user.has_team = True
        user.is_admin = True
        user.is_creator = True
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user and %(team)s has been created!', 
                team=team.teamname), category='success')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        return render_template('auth/register.html', title=_('Register'), form=form,
                                form_creator=form_creator, skip_question=True, creator=creator)
    else:
        return render_template('auth/register.html', title=_('Register'), form=form,
                                form_creator=form_creator)


@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        # Outside the if. This is so that clients cannot use this form to figure out if a given user is a member or not.
        flash(_('Check your email for the instructions to reset your password.'), category='info')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html', title=_('Reset Password'), form=form)


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'), category='success')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)