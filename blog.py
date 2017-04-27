import os
import re
import random
import hashlib
import hmac
from string import letters
import time

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    uname = db.StringProperty()
    likes = db.IntegerProperty()
    liked_by = db.ListProperty(str)
    comments = db.StringListProperty()
    commenter = db.StringListProperty()


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)



class BlogFront(BlogHandler):
    def get(self):

        posts = greetings = Post.all().order('-created')
        user = self.user
        self.render('front.html', posts = posts, u = user)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where ancestor is :1 order by created desc limit 10", key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments=comments)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):

        uname = self.user.name

        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')


        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, uname = uname)
            p.put()
            self.write("Created new post. <a href='/blog'>Go to blog page.</a>")
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class editPost(BlogHandler):
    def get(self, post_id):
        editedPost = Post.get_by_id(int(post_id), parent=blog_key())
        if not self.user:
            self.redirect("/login")

        elif self.user.name == editedPost.uname:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            query = db.get(key)
            self.render("editPost.html", query=query)
        else:
            self.write("You are not allowed to edit this post.<a href='/blog'>Go Back</a>")




    def post(self, post_id):
        editedPost = Post.get_by_id(int(post_id), parent=blog_key())

        if editedPost.uname == self.user.name:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                editedPost.subject = subject
                editedPost.content = content
                editedPost.put()
                time.sleep(.1)
                self.redirect('/blog')
            else:
                error = "subject and content, please!"
                self.render("editPost.html", subject=subject, content=content, error=error)

        else:
            self.write("You are not allowed to edit this post. <a href='/blog'>Go Back</a>")


class deletePost(BlogHandler):
    def get(self, post_id):


        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.uname == self.user.name:
                post.delete()
                self.write("Successfully deleted that post ! <a href='/blog'>Go to blog page</a>")
            else:
                self.write('You are not authorized to delete this post. <a href="/blog">Go Back to blog page.</a>')

        else:
            self.redirect("/login")


class likePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login")

    def post(self, post_id):
        if hasattr(self.user, 'name') == False:
            self.redirect("/login")

        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.likes == None:
                post.likes=0
            uname= post.uname
            logged_user = self.user.name
            if logged_user in post.liked_by:
                post.likes += -1
                post.liked_by.remove(logged_user)
                post.put()
                time.sleep(.1)
                self.redirect('/blog')
            elif uname != logged_user:
                post.likes += 1
                post.liked_by.append(logged_user)
                post.put()
                time.sleep(.1)
                self.redirect('/blog')
            else:
                self.write("Can't like your own post.<a href='/blog'>Go Back</a>")



class NewComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login")

    def post(self, post_id):
        if hasattr(self.user, 'name') == False:
            self.redirect("/login")
        else:
            content = self.request.get('content')
            if content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = Post.get_by_id(int(post_id), parent=blog_key())
                post.comments.append(content)
                post.commenter.append(self.user.name)
                post.put()
                time.sleep(.2)
                self.redirect('/blog')

            else:
                self.redirect('/blog')

class EditComment(BlogHandler):

    def post(self, post_id, index):
        i = int(index)
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if hasattr(self.user, 'name') == False:
            self.redirect("/login")
        elif self.user.name == post.commenter[i]:
            content = self.request.get('content')
            if content:
                post.comments[i] = content
                post.put()
                time.sleep(.2)
                self.redirect('/blog')
            else:
                self.redirect('/blog')

        else:
            self.write("You are not allowed to edit this comment. <a href='/blog'>Go Back</a>")

class DeleteComment(BlogHandler):

    def get(self, post_id, index):
        i = int(index)
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not self.user:
            self.redirect("/login")

        elif self.user.name == post.commenter[i]:
            post.comments.pop(i)
            post.commenter.pop(i)
            post.put()
            time.sleep(.2)
            self.redirect('/blog')
        else:
            self.write('You are not authorized to delete this comment. <a href="/blog">Go Back to blog page.')




class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)



class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')


        params = dict(username = self.username,
                      email = self.email)

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

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):

        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.write("Signed up as "+ self.username + "<br/><a href='/blog'>Go to Blog Page</a>")

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.write("Logged in! <br/><a href='/blog'>Go to Blog Page</a>")
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.write("Logged out !<br/><a href='/blog'>Go to Blog Page</a>")

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', editPost),
                               ('/blog/delete/([0-9]+)', deletePost),
                               ('/blog/like/([0-9]+)', likePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)', DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)', EditComment)
                               ],
                              debug=True)
