from request import BlogRequestHandler

from models import User
from models import Post
from models import Comments

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
