from request import BlogRequestHandler

class Logout(BlogRequestHandler):
	"""
	Logs out the user and redirects to home page
	"""
	def get(self):
		if self.user:
			self.logout()

		self.redirect('/login')
