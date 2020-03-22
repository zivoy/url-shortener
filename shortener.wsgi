#!/usr/bin/python
from shortener import app
import sys
import os
sys.path.insert(0,"/home/zivy/shortner/")


def application(req_environ, start_response):
    os.environ['GithubClientSecret'] = req_environ['GithubClientSecret']
    os.environ['FlaskDevKey'] = req_environ['FlaskDevKey']

    app(req_environ, start_response)
