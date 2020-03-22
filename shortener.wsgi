#!/usr/bin/python
import os
import sys

sys.path.insert(0, "/home/zivy/shortner/")

from shortener import app


def application(req_environ, start_response):
    os.environ['GithubClientSecret'] = req_environ['GithubClientSecret']
    os.environ['FlaskDevKey'] = req_environ['FlaskDevKey']

    app(req_environ, start_response)
