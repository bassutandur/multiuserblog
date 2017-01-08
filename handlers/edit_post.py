import datetime
import time

from google.appengine.ext import db

from request import BlogRequestHandler

from models import User
from models import Post

class EditPost(BlogRequestHandler):
	"""
	This class helps in editing a post
	Only Author of the post can edit it
	"""
	def get(self, post_id):
		key = db.Key().from_path('Post', int(post_id))
		post = db.get(key)
		if post:
			if self.user and post.created_by == self.user.name:
				self.render('edit-post.html', user = self.user, post = post)
			elif self.user:  #malicious user
				self.render('error.html', user = self.user, error = 'You dont have permission to edit this post')
			else:
				self.redirect('/login')
		else:
			self.render('error.html', user = self.user, error = 'Post no longer exists!')

	def post(self, post_id):
		subject = self.request.get('subject')
		content = self.request.get('content')

		key = db.Key().from_path('Post', int(post_id))
		post = db.get(key)

		if post:
			if self.user and post.created_by == self.user.name:
				if subject and content:
					post.subject = subject
					post.content = content
					post.last_modified = datetime.datetime.now()
					post.put()
					self.render('permalink.html', user = self.user, post = post)
				else:
					self.render('edit-post.html', user = self.user, post = post, msg = 'Both fields are mandatory')
			elif self.user:  #malicious user
				self.render('error.html', user = self.user, error = 'You dont have permission to edit this post')
			else: # if not logged-in
				self.redirect('/login')
		else:
			self.render('error.html', user = self.user, error = 'Post no longer exists!')