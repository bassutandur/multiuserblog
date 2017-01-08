from google.appengine.ext import db

from request import BlogRequestHandler

from models import User
from models import Post

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

		if post:
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
					self.sleep()
					self.redirect('/blog')
			else: # User cannot like his own post
				self.render('error.html', user = self.user, error = "You cannot Like your own post")
		else: # Deleted post
			self.render('error.html', user = self.user, error = "Post no longer exists")
