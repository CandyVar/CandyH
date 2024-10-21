import os

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask import redirect
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_restful import Api
from flask_socketio import SocketIO
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from data import db_session
from data.users import User
from forms.user import RegisterForm, LoginForm

app = Flask(__name__, static_folder='static', static_url_path='/static')
api = Api(app)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
APP_TOKEN = 'yandexlyceum_secret_key'
app.config['STATIC_FOLDER'] = './static'
UPLOAD_FOLDER = 'uploads'
UPLOAD_FOLDER_COVERS = 'uploads/covers'  # Добавлено для примера
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER_COVERS'] = UPLOAD_FOLDER_COVERS
covers = app.config['UPLOAD_FOLDER_COVERS']
upload_folder = app.config['UPLOAD_FOLDER']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/blogs.db?check_same_thread=False'
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
login_manager = LoginManager()
login_manager.init_app(app)
socketio = SocketIO(app)
admins = 5
system = 100
com_sys = True
login_manager.login_view = 'login'


def update_user_rank(user_id, new_rank):
    # Инициализация базы данных
    db_sess = db_session.create_session()

    # Найти пользователя по id
    user = db_sess.query(User).filter(User.id == user_id).first()

    if user:
        # Обновить поле rank
        user.rank = new_rank

        # Сохранить изменения
        db_sess.commit()
        print(f"User with id {user_id} updated successfully.")
    else:
        print(f"No user found with id {user_id}.")

    # Закрыть сессию
    db_sess.close()


def get_user_name(user_id):
    # Инициализация базы данных
    db_sess = db_session.create_session()

    # Найти пользователя по id
    user = db_sess.query(User).filter(User.id == user_id).first()

    if user:
        # Возвращаем имя пользователя
        return user.name
    else:
        # Пользователь не найден
        return None

    # Закрыть сессию
    db_sess.close()


@app.route('/')
def main():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'
    return render_template('index.html', title='Главная страница', status=True)


@app.route('/test')
def test():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>alert("Вы были навсегда заблокированны")</script>'
    return render_template('test.html', title='Главная страница', status=True)


@app.route('/api/login', methods=['POST'])
def api_login():
    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    # Создаем сессию для работы с БД
    session: Session = db_session.create_session()

    # Находим пользователя по email
    user = session.query(User).filter(User.email == email).first()

    if user and user.check_password(password) and user.rank > 0:
        return jsonify({"hwid": user.hwid})
    else:
        return jsonify({"success": False}), 401


@app.route('/api/sethwid', methods=['POST'])
def set_hwid():
    data = request.get_json()

    # Проверяем наличие токена в заголовках
    token = request.headers.get('Authorization')
    if token != f"Bearer {APP_TOKEN}":
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    email = data.get('email')
    hwid = data.get('hwid')
    password = data.get('password')  # Добавляем поле для пароля

    # Создаем сессию для работы с БД
    session: Session = db_session.create_session()

    # Находим пользователя по email
    user = session.query(User).filter(User.email == email).first()

    if user:
        # Проверяем правильность пароля
        if user.check_password(password):
            if user.hwid is None or user.hwid == "None":
                user.set_hwid(hwid)
                session.commit()
                return jsonify({"success": True, "message": "HWID updated"})
            else:
                return jsonify({"success": False, "message": "HWID already set"}), 400
        else:
            return jsonify({"success": False, "message": "Invalid password"}), 401
    else:
        return jsonify({"success": False, "message": "User not found"}), 404


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(UPLOAD_FOLDER_COVERS):
    os.makedirs(UPLOAD_FOLDER_COVERS)


@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        elif len(form.password.data) < 3:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Ненадежный пароль")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data,
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        if current_user.rank == -2:
            return '<script>document.location.href = document.referrer</script>'
    logout_user()
    return redirect("/")


@app.route('/uedit')
def users():
    if current_user.rank < admins:
        return '<script>document.location.href = document.referrer</script>'
    db_sess = db_session.create_session()
    users = db_sess.query(User).all()
    return render_template('users_all.html', users=users)


@app.route('/uedit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.rank < admins:
        return '<script>document.location.href = document.referrer</script>'
    db_sess = db_session.create_session()
    user = db_sess.query(User).filter(User.id == user_id).first()
    if not user:
        return '<script>document.location.href = document.referrer</script>'

    if request.method == 'POST':
        user.name = request.form.get('name')
        user.about = request.form.get('about')
        user.hwid = request.form.get('hwid')
        user.rank = int(request.form.get('rank'))
        user.email = request.form.get('email')

        if request.form.get('password'):
            user.set_password(request.form.get('password'))

        db_sess.commit()
        return '<script>document.location.href = document.referrer</script>'

    return render_template('users_edit.html', user=user)


if __name__ == '__main__':
    db_session.global_init("db/blogs.db")
    socketio.run(app, allow_unsafe_werkzeug=True)
