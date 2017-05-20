import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'

no_of_likes = 0


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, val))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# my database definitions begin here


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class PostLikes(db.Model):
    post_id = db.IntegerProperty(required=True)
    author = db.StringProperty(required=True)


class PostComments(db.Model):
    author = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comments = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# database definitions end here


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        int_post_id = int(post_id)

        comments = db.GqlQuery("SELECT * FROM PostComments "+ 
            "WHERE post_id = %s" % (int_post_id,))
        liked = PostLikes.all().filter('post_id =',
                                       int_post_id).filter('author =',
                                                           self.user.name)
        numLikes = PostLikes.all().filter('post_id =', int_post_id)

        user_likes = liked.count()
        total_likes = numLikes.count()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, commentss=comments,
                    user_likes=user_likes, total_likes=total_likes)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/blog')
            return

        else:
            comment = self.request.get('comment')
            author = self.request.cookies.get('username')

            if comment:
                p = PostComments(parent=blog_key(), comments=comment,
                                 author=author, post_id=int(post_id))
                p.put()
                time.sleep(0.5)
                self.redirect('/blog/' + post_id)
                return
            else:
                error = "comment must have some sort of content, please!"
                self.render("permalink.html", comments=comment, error=error,
                            post=post, author=author)
"""           
 order of functions not necessarily order they were done
likes done in a similar way to delete post and delete comments
"""


class Likes(BlogHandler):
    def get(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        author = self.user.name
        int_post_id = int(post_id)

        l = PostLikes(parent=blog_key(), post_id=int_post_id,
                      author=self.user.name)

        # all cases of this post id where this particular user liked
        liked = PostLikes.all().filter('post_id =',
                                       int_post_id).filter('author =', author)

        if not self.user:
            self.redirect('/blog')
            return

        else:
            if liked:

                if not post.author == self.user.name:

                    if liked.count() == 0:

                        l.id = int_post_id
                        l.author = author
                        l.put()
                        time.sleep(0.5)
                        self.redirect('/blog/%s' % str(post_id))
                        return

                    elif liked.count() == 1:
                        # delete record from database
                        db.delete(liked)
                        time.sleep(0.5)
                        self.redirect('/blog/%s' % str(post_id))
                        return

                else:
                    self.write("You cannot like your own posts")

            else:
                self.write("This post no longer exists")


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id),
                               parent=blog_key())
        post = db.get(key)

        content = post.content
        author = post.author
        subject = post.subject

        if not self.user:
            self.redirect('/blog')
            return

        else:
            if post:

                if author == self.user.name:

                    self.render("editpost.html", content=content,
                                subject=subject, author=author, post=post)

                else:
                    error = "You cannot edit what isn't yours"
                    self.render("editpost.html", content=content,
                                subject=subject, author=author, error=error,
                                post=post)

            else:
                error = "This comment does not exist, 404"
                self.render("editpost.html", content=content,
                            subject=subject, author=author, error=error,
                            post=post)

    def post(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        content = post.content
        author = post.author
        subject = post.subject

        if self.request.get("update_post"):
            content = self.request.get('content')
            subject = self.request.get('subject')

            if author == self.user.name:

                if subject and content:

                    post.subject = subject
                    post.content = content
                    post.author = author
                    post.put()

                    time.sleep(0.5)
                    self.redirect('/blog/%s' % str(post_id))
                    return

                else:
                    error = "You need both subject and content please!!!'"
                    self.render(
                        "editpost.html",
                        content=content,
                        error=error)

            else:
                error = "You cannot edit what isn't yours!!!'"
                self.render(
                    "editpost.html",
                    content=content,
                    error=error)

        elif self.request.get("cancel"):
            self.redirect('/blog/%s' % str(post_id))
            return


class DeletePost(BlogHandler):
    def get(self, post_id):

        key = db.Key.from_path('Post', int(post_id),
                               parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/blog')
            return

        else:
            if post:

                if post.author == self.user.name:

                    db.delete(post)
                    time.sleep(0.5)
                    self.redirect('/blog/')

                else:
                    self.write("You cannot delete other user's posts")

            else:
                self.write("This post no longer exists")
"""
used newpost as the template for most of the rest of my code that 
I didn't mention on the Likes comments.  
"""


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")
            return

    def post(self):
        if not self.user:
            self.redirect('/blog')
            return

        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            author = self.request.cookies.get('username')
            print author

            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content, author=author)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
                return
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject,
                            content=content, error=error, author=author)


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        key = db.Key.from_path('PostComments', int(comment_id),
                               parent=blog_key())
        comment = db.get(key)

        key2 = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key2)

        content = comment.comments
        author = comment.author

        if not self.user:
            self.redirect('/blog')
            return
        else:

            if comment:

                if author == self.user.name:

                    self.render("editcomment.html", comment=content,
                                author=author, post=post)

                else:
                    error = "You cannot edit what isn't yours"
                    self.render("editcomment.html", comment=content,
                                error=error, post=post)

            else:
                error = "This comment does not exist, 404"
                self.render("editcomment.html", comment=content, error=error)

    def post(self, post_id, comment_id):

        key = db.Key.from_path('PostComments', int(comment_id),
                               parent=blog_key())
        comment = db.get(key)
        author = comment.author
        post_id = comment.post_id

        if self.request.get("update_comment"):

            if author == self.user.name:

                comment.comments = self.request.get('comment')
                comment.author = author
                comment.put()

                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_id))
                return

            else:
                error = "You cannot edit what isn't yours!!!'"
                self.render(
                    "editcomment.html",
                    comment=content,
                    edit_error=error)

        elif self.request.get("cancel"):
            self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):

        key = db.Key.from_path('PostComments', int(comment_id),
                               parent=blog_key())
        comment = db.get(key)
        post_id = comment.post_id
        print comment.author

        if not self.user:
            self.redirect('/blog')
            return

        else:
            if comment:

                if comment.author == self.user.name:

                    db.delete(comment)

                    time.sleep(0.5)
                    self.redirect('/blog/%s' % str(post_id))
                    return

                else:
                    self.write("You cannot delete other user's comments")

            else:
                self.write("This comment no longer exists")


# Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        usern = str(self.username)

        self.set_cookie('username', usern)
        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)

        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')
            return


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        usern = str(username)

        self.set_cookie('username', usern)

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
            return

        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/login')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/blog/signup')
            return


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ('/blog/([0-9]+)/likes', Likes),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/([0-9]+)/([0-9]+)/delete',
                                DeleteComment),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ],
                              debug=True)
