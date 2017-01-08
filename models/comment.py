from google.appengine.ext import db

#db class
class Comments(db.Model):
	"""
	Data Model that defines the properties of the comments
	"""
	comment = db.StringProperty(required = True)
	post_id = db.IntegerProperty(required = True)
	comment_by = db.StringProperty(required = True)
	count = db.IntegerProperty(required = True, default = 0)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
