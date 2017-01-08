from request import BlogRequestHandler

import re

from models import User

# User registration validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def match_passwords(password1, password2):
	return password1 == password2

class Register(BlogRequestHandler):
	"""
	This class validates new user registration
	"""
	def get(self):
		if self.user:
			self.redirect('/blog')
		else:
			self.render("signup.html")

	def post(self):
		#self.render("register.html")
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		error = False
		params = {}
		
		if not valid_username(self.username):
			params["error_username"] = "Not a valid Username"
			error = True
		if not valid_password(self.password):
			params["error_password"] = "Not a valid Password"
			error = True
		if not match_passwords(self.password, self.verify):
			params["error_verify"] = "Passwords didn't match"
			error = True
		if not valid_email(self.email):
			params["error_email"] = "That's not a valid email address"
			error = True

		if error:
			self.render("signup.html", **params)
		else:
			self.done() # indicates validation is successful

	def done(self, *a, **kw):
		raise NotImplementedError

class Signup(Register):
	"""
	Implements actual registration process once validation is successful from baseclass
	"""
	def done(self):
		u = User.by_name(self.username)
		#self.write(u)
		if u:
			self.render("signup.html", error_username = "Username already exists")
		else:
			#self.write(self.email)
			user = User.register(self.username, self.password, self.email)
			user.put()

			#login and redirect to blog
			self.login(user)
			self.redirect('/blog')

