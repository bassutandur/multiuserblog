from google.appengine.ext import db

from request import BlogRequestHandler

from models import User
from models import Post
from models import Comments

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

		if c:
			if self.user and c and c.comment_by == self.user.name:
				self.render('edit-comment.html', user = self.user, comment = c)
			else:  # malcious user
				self.render('error.html', user = self.user, error = 'You are not allowed to edit this comment')
		else:
			self.render('error.html', user = self.user, error = 'Comment no longer exists!')

	def post(self, comment_id):
		comment_str = self.request.get('comment')

		key = db.Key.from_path('Comments', int(comment_id))
		c = db.get(key)

		if c:
			if comment_str and self.user and c.comment_by == self.user.name:
				#comment_str = comment_str.replace('\n', '<br/>')
				c.comment = comment_str 
				c.put()
				self.sleep()
				self.redirect('/blog')
			else:
				self.render('edit-comment.html', user = self.user, comment = c, msg = 'Please Enter Something')
		else:
			self.render('error.html', user = self.user, error = 'Comment no longer exists!')
