import os

import datetime
import time

import hashlib
import hmac

import random

import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							  autoescape = True)

#Added to handle GAE App engine's issue
SLEEP_TIME = 0.5

SECRET = "This;is;very;secret;"

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

# Make secure value for username with secret message
def make_secure_val(val):
	hex = hmac.new(SECRET, val).hexdigest()
	return '%s|%s' % (val, hex)

# Login validation
def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

# salt to make password strong
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

# Make secure password 
def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()

	return '%s,%s' % (salt, h)

# validate user entered password
def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

#db class
class User(db.Model):
	"""
	Data Model that defines User of the blog
	"""
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		#user = db.GqlQuery("SELECT * FROM User WHERE name = :1", name)
		user = User.all().filter('name =', name).get()
		return user

	@classmethod
	def register(cls, name, pw, email = None):
			pw_hash = make_pw_hash(name, pw)
			return User(parent = users_key(),
						name = name,
						pw_hash = pw_hash,
						email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

#db class
class Post(db.Model):
	"""
	Data Model that defines properties of the blog post
	"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created_by = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	likes = db.IntegerProperty(default = 0)
	likes_by = db.StringListProperty(str,default = [])

#db class
class Comments(db.Model):
	"""
	Data Model that defines the properties of the comments
	"""
	comment = db.StringProperty(required = True)
	post_id = db.IntegerProperty(required = True)
	comment_by = db.StringProperty(required = True)
	count = db.IntegerProperty(required = True, default = 0)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)



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

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

#Default handler, redirects to home page
class MainPage(BlogRequestHandler):
	def get(self):
		self.redirect('/blog')

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

class Login(BlogRequestHandler):
	"""
	Handles login process
	Redirect to blog's home page on success
	Redirect to login page with error message on failure
	"""
	def get(self):
		if self.user:
			self.redirect('/blog')
		else:
			self.render('login.html') # if not logged in, redirect to login page

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			self.render('login.html', invalid_login = 'Invalid login')

class Logout(BlogRequestHandler):
	"""
	Logs out the user and redirects to home page
	"""
	def get(self):
		if self.user:
			self.logout()

		self.redirect('/blog')

class BlogFront(BlogRequestHandler):
	"""
	This class represents front page of the blog
	"""
	def get(self):
		user = None
		posts = Post.all().order('-created')
		comments = Comments.all().order('-created')
		if(self.user):
			user = self.user
		self.render('blog.html', user = user, posts = posts, comments = comments)

	def post(self):
		self.render('blog.html')

class NewPost(BlogRequestHandler):
	"""
	Handles new post to be added by user
	"""
	def get(self):
		if self.user:
			self.render('post-form.html', user = self.user)
		else:
			self.redirect('/login')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')
		if subject and content:
			p = Post(subject = subject, content = content, created_by = self.user.name)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))  # redirect to permalink
		else:
			msg = 'Both fields are mandatory'
			self.render('post-form.html', msg = msg)

class PostPage(BlogRequestHandler):
	"""
	Represents permalink for the new post added
	"""
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id))
		post = db.get(key)

		if not post:
			self.error(404)
			return
		self.render('permalink.html', user = self.user, post = post)

class DeletePost(BlogRequestHandler):
	"""
	Class to delete a post by the user
	This class checks if user has the permission to delete it before deleting
	"""
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id))
		post = db.get(key)
		if(self.user and post and post.created_by == self.user.name):
			# Delete all the comments for the post
			comments = db.GqlQuery('SELECT * from Comments WHERE post_id = :1 ', int(post_id))
			for comment in comments:
				comment.delete()

			#Delete the post
			post.delete()
			time.sleep(SLEEP_TIME)
			self.redirect('/blog')
		elif self.user and post:  #malicious user
			self.render('error.html', error = 'You cannot delete post created by another user')
		else:
			self.redirect('/login')

class EditPost(BlogRequestHandler):
	"""
	This class helps in editing a post
	Only Author of the post can edit it
	"""
	def get(self, post_id):
		key = db.Key().from_path('Post', int(post_id))
		post = db.get(key)
		if self.user and post and post.created_by == self.user.name:
			self.render('edit-post.html', user = self.user, post = post)
		elif self.user:  #malicious user
			self.render('error.html', user = self.user, error = 'You dont have permission to edit this post')
		else:
			self.redirect('/login')

	def post(self, post_id):
		subject = self.request.get('subject')
		content = self.request.get('content')

		key = db.Key().from_path('Post', int(post_id))
		post = db.get(key)

		if subject and content:
			post.subject = subject
			post.content = content
			post.last_modified = datetime.datetime.now()
			post.put()
			self.render('permalink.html', user = self.user, post = post)
		else:
			self.render('edit-post.html', user = self.user, post = post, msg = 'Both fields are mandatory')

class AddComments(BlogRequestHandler):
	"""
	Class to add comments for the post
	Only logged in user can post comments
	"""
	def get(self):
		self.write('Hello comments')
	def post(self, post_id):
		comment = self.request.get('comment')
		comment = comment.replace('\n', '<br/>')
		if comment and self.user:
			post_id = int(post_id)
			c = Comments(comment = comment, post_id = post_id, comment_by = self.user.name)
			c.put()
			time.sleep(SLEEP_TIME)
			self.redirect('/blog')
		else:
			self.redirect('/login')

class DeleteComment(BlogRequestHandler):
	"""
	This class helps in deleting a comment
	Only Author of the comment can delete it
	"""
	def get(self, comment_id):
		key = db.Key.from_path('Comments', int(comment_id))
		comment = db.get(key)
		if(self.user and comment and comment.comment_by == self.user.name):
			comment.delete()
			time.sleep(SLEEP_TIME) 
			self.redirect('/blog')
		elif self.user:  #malicious user
			self.render('error.html', user = self.user, error = 'You cannot delete comments posted by other users')
		else:
			self.redirect('/login')

class EditComment(BlogRequestHandler):
	"""
	Class to edit the comments
	Only autor of the comment can edit it
	"""
	def get(self, comment_id):
		key = db.Key.from_path('Comments', int(comment_id))
		c = db.get(key)

		if not self.user:
			self.redirect('/login')


		if self.user and c and c.comment_by == self.user.name:
			self.render('edit-comment.html', user = self.user, comment = c)
		else:  # malcious user
			self.render('error.html', user = self.user, error = 'You cannot edit comments posted by other users')

	def post(self, comment_id):
		comment_str = self.request.get('comment')

		key = db.Key.from_path('Comments', int(comment_id))
		c = db.get(key)

		if comment_str and self.user and c.comment_by == self.user.name:
			#comment_str = comment_str.replace('\n', '<br/>')
			c.comment = comment_str 
			c.put()
			time.sleep(SLEEP_TIME)
			self.redirect('/blog')
		else:
			self.render('edit-comment.html', user = self.user, comment = c, msg = 'Please Enter Something')

class LikePost(BlogRequestHandler):
	"""
	Class to Like posts
	Only logged-in user can like
	A user cannot like his own post
	"""
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id))
		post = db.get(key)

		if not self.user:
			self.redirect('/login')
			return

		if self.user and post.created_by != self.user.name:
			likes_by_list = post.likes_by
			post_already_liked = False
			for user in likes_by_list:
				if user == self.user.name:
					post_already_liked = True
			if post_already_liked:  # do not allow if already liked
				self.render('error.html', user = self.user, error = "You have already Liked this post")
			else:
				likes = post.likes
				likes = likes + 1;
				post.likes_by.append(self.user.name)
				post.likes = likes
				post.put()
				time.sleep(SLEEP_TIME)
				self.redirect('/blog')
		else: # User cannot like his own post
			self.render('error.html', user = self.user, error = "You cannot Like your own post")

app = webapp2.WSGIApplication([('/', MainPage),
								('/register', Signup),
								('/login', Login),
								('/logout', Logout),
								('/blog/?', BlogFront),
								('/blog/editpost/([0-9]+)', EditPost),
								('/blog/likepost/([0-9]+)', LikePost),
								('/blog/deletepost/([0-9]+)', DeletePost),
								('/blog/addcomments/([0-9]+)', AddComments),
								('/blog/deletecomment/([0-9]+)', DeleteComment),
								('/blog/editcomment/([0-9]+)', EditComment),
								('/blog/([0-9]+)', PostPage),
								('/blog/newpost', NewPost),
								 ], debug=True)
