from google.appengine.ext import db

#db class
class Post(db.Model):
	"""
	Data Model that defines properties of the blog post
	"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created_by = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	likes = db.IntegerProperty(default = 0)
	likes_by = db.StringListProperty(str,default = [])
