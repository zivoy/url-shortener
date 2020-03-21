import base64
import random
import re
from datetime import datetime

import psycopg2
import psycopg2.extensions
import requests
from flask import Flask, request, redirect, render_template, abort, jsonify
from requests.exceptions import Timeout

app = Flask(__name__)
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


def connect() -> psycopg2.extensions.connection:
    return psycopg2.connect(host="localhost", database="shorten-urls", user="python", password="1111")


def exists(name: str, courser: psycopg2.extensions.cursor) -> bool:
    courser.execute("SELECT EXISTS(SELECT 1 FROM urls WHERE shortened=%(name)s);", {"name": name})
    return courser.fetchone()[0]


def get(name: str, courser: psycopg2.extensions.cursor) -> str:
    courser.execute("SELECT url FROM urls WHERE shortened=%(name)s", {"name": name})
    return courser.fetchone()[0]


def add(connection: psycopg2.extensions.connection, shortened: str, url: str,
        author: str = None, creation_date: datetime = None):
    curr: psycopg2.extensions.cursor = connection.cursor()

    # if author is None:
    #     author = "NULL"

    if creation_date is not None:
        # creation_date = "NULL"
        # else:
        creation_date = f"'{creation_date.strftime('%Y-%m-%d %H:%M:%S')}'"

    curr.execute("INSERT INTO urls (shortened, url, creation_date, author) VALUES "
                 "(%(shortened)s, %(url)s, %(creation_date)s, %(author)s)",
                 {"shortened": shortened, "url": url, "creation_date": creation_date, "author": author})
    connection.commit()
    curr.close()


def get_id(url, curr):
    val = 0
    for i, j in enumerate(url):
        val += (i + 1) * ord(j) * 314159265359
    num = int(((val % 10 ** 10) - 1000) / 10 ** 10 * 10 ** 6) + 1000
    short = base64.urlsafe_b64encode(str(num).encode()).decode()
    if not exists(short, curr):
        return short
    if get(short, curr) == url:
        return short
    while True:
        num = random.randint(1000, 999999)
        short = base64.urlsafe_b64encode(str(num).encode()).decode()
        if not exists(short, curr):
            return short


def get_table(curr: psycopg2.extensions.cursor, author: str = None):
    if author is None:
        curr.execute("SELECT * FROM urls")
    else:
        curr.execute("SELECT * FROM urls WHERE LOWER(author)=%(author)s", {"author": author.lower()})
    return curr.fetchall()


@app.route("/")
def home_page():
    return "Url Shortener<br/><a href='/list'>list shortened links</a><br/><a href='/new'>add new shortend link</a>"


@app.route("/<url>")
def redirect_path(url):
    connection = connect()
    curr = connection.cursor()
    if not exists(url, curr):
        returned_value = f"\"{url}\" is not valid"
    else:
        long_url = get(url, curr)
        returned_value = redirect(long_url, 301)
    curr.close()
    connection.close()
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

    connection = connect()
    curr = connection.cursor()

    if "short" in request.json and request.json["short"] is not None:
        short = request.json["short"]
        if short in ["new", "list"]:
            curr.close()
            connection.close()
            abort(401)
    else:
        short = get_id(url, curr)

    if not exists(short, curr):
        add(connection, short, url, author, datetime.now())
    elif "short" in request.json and request.json["short"] is not None:
        curr.close()
        connection.close()
        abort(401)
    curr.close()
    connection.close()
    return jsonify({"id": short})


@app.route("/n", methods=["GET"])
@app.route("/new", methods=["GET"])
def new_form():
    return render_template("newentryfourm.html", baseUrl=request.url_root)
    # "form thing " + str(request.args.get("author"))


@app.route("/api/list", methods=["POST"])
def list_urls():
    if not request.json:
        abort(400)

    if 'author' not in request.json:
        author = None
    else:
        author = request.json['author']

    connection = connect()
    curr = connection.cursor()

    tbl = get_table(curr, author)

    table = [{"short": i[0],
              "url": i[1],
              "author": i[3],
              "date": i[2]} for i in tbl]

    curr.close()
    connection.close()
    return jsonify(table)


@app.route("/list")
def render_table():
    author = request.args.get("author")
    res = requests.post(request.url_root + 'api/list', json={"author": author})
    return render_template("all columns table.html", name=author, table=res.json())


if __name__ == '__main__':
    app.run()
