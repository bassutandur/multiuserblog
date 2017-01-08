from google.appengine.ext import db

from request import BlogRequestHandler

from models import User
from models import Post

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
		if self.user:
			subject = self.request.get('subject')
			content = self.request.get('content')
			if subject and content:
				p = Post(subject = subject, content = content, created_by = self.user.name)
				p.put()
				self.redirect('/blog/%s' % str(p.key().id()))  # redirect to permalink
			else:
				msg = 'Both fields are mandatory'
				self.render('post-form.html', msg = msg)
		else:
			self.redirect('/login')

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
