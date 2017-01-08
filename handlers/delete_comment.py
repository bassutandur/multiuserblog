from google.appengine.ext import db

from request import BlogRequestHandler

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
			self.sleep() 
			self.redirect('/blog')
		elif self.user:  #malicious user
			self.render('error.html', user = self.user, error = 'You cannot delete comments posted by other users')
		else:
			self.redirect('/login')
