from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# JINJA ENV VARIABLE
app.jinja_env.globals["LOGGED_IN"] = False
app.jinja_env.globals["IS_ADMIN"] = False

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABSE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    posts = db.relationship("BlogPost", back_populates="user")
    comments = db.relationship("Comment", back_populates="user")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = db.relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = db.relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


def admin_only(function):
    @wraps(function)
    def inner_function(*args, **kwargs):
        if app.jinja_env.globals["IS_ADMIN"]:
            function(*args, **kwargs)
        return abort(403)
    return inner_function


@login_manager.user_loader
def load_user(user_id):
    app.jinja_env.globals["LOGGED_IN"] = True
    return User.query.get(user_id)


@app.route('/')
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get("email")).first():
            flash("User with this email already exists, log in instead!")
            return redirect(url_for('login'))

        new_user = User()
        new_user.name = request.form.get("name")
        new_user.email = request.form.get("email")
        new_user.password = generate_password_hash(password=request.form.get("password"), method="pbkdf2:sha256", salt_length=8)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('home'))

    form = RegisterForm()
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get("email")).first()

        if not user:
            flash("No registered user with this email!")
            return redirect(url_for('login'))

        if check_password_hash(user.password, request.form.get("password")):
            login_user(user)
            print(user.id)
            if user.id == 1:
                app.jinja_env.globals["IS_ADMIN"] = True
                print(app.jinja_env.globals["IS_ADMIN"])
            return redirect(url_for('home'))

        flash("Incorrect password!")
        return redirect(url_for('login'))

    form = LoginForm()
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    app.jinja_env.globals["LOGGED_IN"] = False
    app.jinja_env.globals["IS_ADMIN"] = False
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    if request.method == "POST":
        new_comment = Comment(
            text=request.form.get("body"),
            user=current_user,
            parent_post=BlogPost.query.get(post_id)
        )

        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    print(Comment.query.filter_by(post_id=post_id).all())
    return render_template("post.html", post=requested_post, form=form, comments=Comment.query.filter_by(post_id=post_id).all())


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@admin_only
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            user=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))

    return render_template("make-post.html", form=form)


@admin_only
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        user=post.user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.user = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
