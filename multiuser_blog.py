import webapp2

from google.appengine.ext import db

from models import user
from models import post
from models import comment

from handlers import BlogRequestHandler
from handlers import BlogFront
from handlers import Signup
from handlers import Login
from handlers import Logout
from handlers import NewPost
from handlers import PostPage
from handlers import EditPost
from handlers import DeletePost
from handlers import AddComments
from handlers import DeleteComment
from handlers import EditComment
from handlers import LikePost

#Default handler, redirects to home page
class MainPage(BlogRequestHandler):
	def get(self):
		self.redirect('/blog')

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
