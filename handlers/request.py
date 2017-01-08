import os

import time

import hmac
import re

from models import User

import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), '../templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							  autoescape = True)

SECRET = "This;is;not;very;secret;"

# Make secure value for username with secret message
def make_secure_val(val):
	hex = hmac.new(SECRET, val).hexdigest()
	return '%s|%s' % (val, hex)

# Login validation
def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

#Added to handle GAE App engine's issue
SLEEP_TIME = 0.5

class BlogRequestHandler(webapp2.RequestHandler):
	"""
	Base class for all the requests
	"""

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_post(response, post):
		response.out.write('<b>' + post.subject + '</b><br>')
		response.out.write(post.content)

	def set_secure_cookie(self, name, val):  # set user name in cookie
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
				'Set-Cookie', 
				'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):  # validate and return user name from cookie
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def sleep(self):
		time.sleep(SLEEP_TIME)

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
