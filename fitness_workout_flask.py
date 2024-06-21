from flask import Flask, render_template, request, redirect, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a more secure key

DATABASE = 'fitnessdb.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['userid']
            session['email'] = user['email']
            flash('Login successful!', 'success')
            return redirect('/comment_wall')
        else:
            error = 'User not found or incorrect password'
            return render_template('login_fitness_webapp.html', error=error)
    return render_template('login_fitness_webapp.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        if user:
            error = 'Duplicate account registration'
            return render_template('register_fitness_webapp.html', error=error)
        hashed_password = generate_password_hash(password, method='sha256')
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        flash('Successfully registered!', 'success')
        return redirect('/')
    return render_template('register_fitness_webapp.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/comment_wall', methods=['GET', 'POST'])
def comment_wall():
    if 'user_id' not in session:
        return redirect('/')

    comment_type = request.args.get('type', 'workout')
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if not title or not content:
            flash('Title / Content is empty', 'error')
        else:
            cursor.execute("INSERT INTO comments (title, content, userid, commentType) VALUES (?, ?, ?, ?)",
                           (title, content, session['user_id'], comment_type))
            conn.commit()
            flash('Comment saved successfully', 'success')

    cursor.execute(
        "SELECT comments.title, comments.content, users.email FROM comments JOIN users ON comments.userid = users.userid WHERE comments.commentType=?",
        (comment_type,))
    comments = cursor.fetchall()

    if comment_type == 'diet':
        return render_template('diet_comment_wall_fitness_webapp.html', comments=comments)
    return render_template('comment_wall_fitness_webapp.html', comments=comments)

if __name__ == '__main__':
    app.run(debug=True)
