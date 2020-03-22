import base64
import os
import random
import re
from datetime import datetime

import psycopg2
import psycopg2.extensions
import requests
from flask import Flask, request, redirect, render_template, abort, \
    jsonify, g, session, render_template_string
from flask_github import GitHub
from requests.exceptions import Timeout

app = Flask(__name__)
app.secret_key = os.getenv("FlaskDevKey")
app.config['GITHUB_CLIENT_ID'] = "76649f9c931b9cd7d396"
app.config['GITHUB_CLIENT_SECRET'] = os.getenv("GithubClientSecret")

address = "localhost"  # "192.168.86.30"

github = GitHub(app)

"""
CREATE TABLE urls(
shortend        VARCHAR(25) PRIMARY KEY  NOT NULL,
url             TEXT                     NOT NULL,
creation_date   TIMESTAMP,
author          TEXT
);

CREATE TABLE users(
id                  INTEGER  PRIMARY KEY  NOT NULL,
github_access_token VARCHAR(255)          NOT NULL,
github_id           INTEGER,
github_login        VARCHAR(255),
authority_level     SMALLINT NOT NULL CHECK (authority_level >= 0)
);
"""

authority_levels = {0: "Not Logged in",
                    1: "Basic Member",
                    2: "Advanced Member"}


class User:
    query = 'SELECT id, github_access_token, github_id, github_login, authority_level ' \
            'FROM users WHERE {colname}=%({colname})s'

    def __init__(self, uid, github_access_token, github_id, github_login, authority_level):
        self.id = uid
        self.github_access_token = github_access_token
        self.github_id = github_id
        self.github_login = github_login
        self.authority_level = authority_level

    @staticmethod
    def get_by_id(uid):
        # g.curr.execute("SELECT id, github_access_token, github_id, github_login, authority_level"
        #                " FROM users WHERE id=%(uid)s", {"uid": uid})
        g.curr.execute(User.query.format(colname="id"), {"id": uid})

        usr = g.curr.fetchone()
        if usr is not None:
            return User(*usr)

    @staticmethod
    def get_by_access_token(github_access_token):
        # g.curr.execute("SELECT id, github_access_token, github_id, github_login, authority_level"
        #                " FROM users WHERE github_access_token=%(github_access_token)s",
        #                {"github_access_token": github_access_token})
        g.curr.execute(User.query.format(colname="github_access_token"),
                       {"github_access_token": github_access_token})

        usr = g.curr.fetchone()
        if usr is not None:
            return User(*usr)

    @staticmethod
    def get_by_github_id(github_id):
        g.curr.execute(User.query.format(colname="github_id"),
                       {"github_id": github_id})

        usr = g.curr.fetchone()
        if usr is not None:
            return User(*usr)

    @staticmethod
    def only_token(github_access_token):
        g.curr.execute("SELECT COUNT(id) FROM users")
        uid = g.curr.fetchone()[0]
        return User(uid, github_access_token, None, None, 1)

    def add_to_table(self):
        g.curr.execute("INSERT INTO users (id, github_access_token, github_id, github_login, authority_level) VALUES "
                       "(%(id)s::integer, %(github_access_token)s, %(github_id)s, "
                       "%(github_login)s, %(authority_level)s::smallint);",
                       {"id": self.id, "github_access_token": self.github_access_token, "github_id": self.github_id,
                        "github_login": self.github_login, "authority_level": self.authority_level})
        g.db.commit()

    def update(self):
        g.curr.execute("UPDATE users SET (github_access_token, github_id, github_login, authority_level)="
                       "(%(github_access_token)s,%(github_id)s,%(github_login)s,%(authority_level)s::smallint)"
                       "WHERE id=%(id)s::integer;",
                       {"id": self.id, "github_access_token": self.github_access_token, "github_id": self.github_id,
                        "github_login": self.github_login, "authority_level": self.authority_level})
        g.db.commit()


urlRE = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def validate_url(url):
    if re.match(urlRE, url) is not None:
        try:
            req = requests.get(url, timeout=1)
        except Timeout:
            return False

        if req.status_code == 200:
            return True
    return False


@app.before_request
def before_request():
    g.db = psycopg2.connect(host=address, database="shorten-urls", user="python", password="1111")
    g.curr = g.db.cursor()
    g.user = None
    if "user_id" in session:
        g.user = User.get_by_id(session['user_id'])


@app.teardown_request
def teardown_request(exception):
    g.db.close()
    g.curr.close()


def url_exists(name: str) -> bool:
    g.curr.execute("SELECT EXISTS(SELECT 1 FROM urls WHERE shortened=%(name)s);", {"name": name})
    return g.curr.fetchone()[0]


def get_url(name: str) -> str:
    g.curr.execute("SELECT url FROM urls WHERE shortened=%(name)s", {"name": name})
    return g.curr.fetchone()[0]


def add_url(shortened: str, url: str, author: str = None, creation_date: datetime = None):
    # if author is None:
    #     author = "NULL"

    if creation_date is not None:
        # creation_date = "NULL"
        # else:
        creation_date = f"'{creation_date.strftime('%Y-%m-%d %H:%M:%S')}'"

    g.curr.execute("INSERT INTO urls (shortened, url, creation_date, author) VALUES "
                   "(%(shortened)s, %(url)s, %(creation_date)s, %(author)s)",
                   {"shortened": shortened, "url": url, "creation_date": creation_date, "author": author})
    g.db.commit()


def get_id(url):
    val = 0
    for i, j in enumerate(url):
        val += (i + 1) * ord(j) * 314159265359
    num = int(((val % 10 ** 10) - 1000) / 10 ** 10 * 10 ** 6) + 1000
    short = base64.urlsafe_b64encode(str(num).encode()).decode()
    if not url_exists(short):
        return short
    if get_url(short) == url:
        return short
    while True:
        num = random.randint(1000, 999999)
        short = base64.urlsafe_b64encode(str(num).encode()).decode()
        if not url_exists(short):
            return short


def get_table(author: str = None):
    if author is None:
        g.curr.execute("SELECT shortened, url, author, creation_date FROM urls")
    else:
        g.curr.execute("SELECT shortened, url, author, creation_date FROM urls WHERE LOWER(author)=%(author)s",
                       {"author": author.lower()})
    return [{"short": i[0],
             "url": i[1],
             "author": i[2],
             "date": i[3]} for i in g.curr.fetchall()]


@app.route("/")
def home_page():
    t = "Url Shortener<br/>"
    if g.user:
        t += f"Level: {authority_levels[g.user.authority_level]}<br/>"
        t += f'Hello! {g.user.github_login} <a href="{{{{ url_for("user") }}}}">Get user</a> ' \
             '<a href="{{ url_for("logout") }}">Logout</a>'
    else:
        t += f"Level: {authority_levels[0]}<br/>"
        t += 'Hello! <a href="{{ url_for("login") }}">Login</a>'
    t += "<br/><a href='/list'>list shortened links</a><br/><a href='/new'>add new shortend link</a>"

    return render_template_string(t)


@github.access_token_getter
def token_getter():
    if g.user is not None:
        return g.user.github_access_token


@app.route("/<url>")
def redirect_path(url):
    if not url_exists(url):
        returned_value = f"\"{url}\" is not valid"
    else:
        long_url = get_url(url)
        returned_value = redirect(long_url, 301)
    return returned_value


@app.route("/api/new", methods=["POST"])
def add_new():
    if not request.json or 'url' not in request.json:
        abort(400)

    url = request.json["url"]
    # request.query_string.decode()
    if not validate_url(url):
        # return f"\"{url}\" is not a valid url"
        abort(400)

    if "author" in request.json:
        author = request.json["author"]
    else:
        author = None

    if "short" in request.json and request.json["short"] is not None:
        short = request.json["short"]
        if short in ["new", "list", "login", "logout", "user", "github-callback"]:
            abort(401)
    else:
        short = get_id(url)

    if not url_exists(short):
        add_url(short, url, author, datetime.now())
    elif "short" in request.json and request.json["short"] is not None:
        abort(401)
    return jsonify({"id": short})


@app.route("/n", methods=["GET"])
@app.route("/new", methods=["GET"])
def new_form():
    author = "Unregistered"
    level = 0
    if g.user:
        author = g.user.github_login
        level = g.user.authority_level
    return render_template("newentryfourm.html", baseUrl=request.url_root, author=author, authority_level=level)
    # "form thing " + str(request.args.get("author"))


@app.route("/api/list", methods=["POST"])
def list_urls():
    if not request.json:
        abort(400)

    if 'author' not in request.json:
        author = None
    else:
        author = request.json['author']

    table = get_table(author)

    return jsonify(table)


@app.route("/list")
def render_table():
    authority_level = 0
    author = None
    if g.user:
        authority_level = g.user.authority_level
        author = g.user.github_login
    if author is None:
        author = "Unregistered"

    if authority_level >= 2:
        auth_arg = request.args.get("author")
        if auth_arg is not None:
            author = auth_arg

    if author == "*":
        author = None

    res = requests.post(request.url_root + 'api/list', json={"author": author})
    return render_template("all columns table.html", name=author, table=res.json())


@app.route('/login')
def login():
    if session.get('user_id', None) is None:
        return github.authorize()
    else:
        return 'Already logged in'


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect("/")


@app.route('/user')
def user():
    return jsonify(github.get('/user'))


@app.route('/github-callback')
@github.authorized_handler
def authorized(access_token):
    next_url = request.args.get('next') or "/"
    if access_token is None:
        return redirect(next_url)

    g.user = User.only_token(access_token)
    github_user = github.get('/user')

    curr_user = User.get_by_github_id(github_user['id'])
    if curr_user is None:
        curr_user = User.only_token(access_token)
        curr_user.add_to_table()

    curr_user.github_access_token = access_token

    # Not necessary to get these details here
    # but it helps humans to identify users easily.
    g.user = curr_user
    curr_user.github_id = github_user['id']
    curr_user.github_login = github_user['login']

    g.user.update()

    session['user_id'] = curr_user.id
    return redirect(next_url)


if __name__ == '__main__':
    app.run()
