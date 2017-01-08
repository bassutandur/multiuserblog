import datetime
import time

from google.appengine.ext import db

from models import Comments

from request import BlogRequestHandler

class AddComments(BlogRequestHandler):
	"""
	Class to add comments for the post
	Only logged in user can post comments
	"""
	def get(self):
		self.write('Hello comments')
	def post(self, post_id):
		comment = self.request.get('comment')

		key = db.Key().from_path('Post', int(post_id))
		post = db.get(key)
		if comment:
			if self.user and post:
				post_id = int(post_id)
				c = Comments(comment = comment, post_id = post_id, comment_by = self.user.name)
				c.put()
				self.sleep()
				self.redirect('/blog')
			elif self.user:
				self.render('error.html', user = self.user, error = 'Post does not exist')
			else:
				self.redirect('/login')
		else:
			self.render('error.html', user = self.user, error = 'Comment cannot be empty')