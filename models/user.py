import hashlib
import hmac

import random

import re
from string import letters

from google.appengine.ext import db

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

# helper methods
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

# salt to make password strong
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

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
