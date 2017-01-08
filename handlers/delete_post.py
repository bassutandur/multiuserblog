from google.appengine.ext import db

from request import BlogRequestHandler

from models import User
from models import Post
from models import Comments

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
			self.sleep()
			self.redirect('/blog')
		elif self.user and post:  #malicious user
			self.render('error.html', error = 'You cannot delete post created by another user')
		else:
			self.redirect('/login')
