from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Замените на свой секретный ключ

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Создание базы данных и таблицы пользователей
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Класс пользователя
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    user = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return User(user[0], user[1], user[2])
    return None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Проверка существования пользователя
        if c.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Пользователь с таким именем уже существует')
            return redirect(url_for('register'))
        
        if c.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email уже зарегистрирован')
            return redirect(url_for('register'))
        
        # Хеширование пароля и сохранение пользователя
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                 (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Регистрация успешна! Теперь вы можете войти.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        user = c.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            return redirect(url_for('profile'))
        
        flash('Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Подключаемся к базе данных
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Проверяем текущий пароль
        user = c.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
        
        if not check_password_hash(user[3], current_password):
            flash('Неверный текущий пароль', 'error')
            conn.close()
            return redirect(url_for('edit_profile'))

        # Проверяем уникальность username и email
        username_exists = c.execute('SELECT id FROM users WHERE username = ? AND id != ?', 
                                  (username, current_user.id)).fetchone()
        email_exists = c.execute('SELECT id FROM users WHERE email = ? AND id != ?', 
                               (email, current_user.id)).fetchone()

        if username_exists:
            flash('Это имя пользователя уже занято', 'error')
            conn.close()
            return redirect(url_for('edit_profile'))

        if email_exists:
            flash('Этот email уже используется', 'error')
            conn.close()
            return redirect(url_for('edit_profile'))

        # Обновляем информацию пользователя
        if new_password and confirm_password:
            if new_password != confirm_password:
                flash('Новые пароли не совпадают', 'error')
                conn.close()
                return redirect(url_for('edit_profile'))
            
            # Обновляем все данные включая пароль
            hashed_password = generate_password_hash(new_password)
            c.execute('''
                UPDATE users 
                SET username = ?, email = ?, password = ?
                WHERE id = ?
            ''', (username, email, hashed_password, current_user.id))
        else:
            # Обновляем только имя и email
            c.execute('''
                UPDATE users 
                SET username = ?, email = ?
                WHERE id = ?
            ''', (username, email, current_user.id))

        conn.commit()
        conn.close()

        # Обновляем объект current_user
        current_user.username = username
        current_user.email = email

        flash('Профиль успешно обновлен', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)