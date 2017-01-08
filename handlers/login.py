from request import BlogRequestHandler

from models import User

class Login(BlogRequestHandler):
	"""
	Handles login process
	Redirect to blog's home page on success
	Redirect to login page with error message on failure
	"""
	def get(self):
		if self.user:
			self.redirect('/blog')
		else:
			self.render('login.html') # if not logged in, redirect to login page

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			self.render('login.html', invalid_login = 'Invalid login')

