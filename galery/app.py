from flask import *
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length
from PIL import Image, ImageDraw, ImageFont
from dotenv import dotenv_values
import io, base64, random, boto3, mysql.connector
import hashlib, bcrypt, time, re

env_vars = dotenv_values('.env')
app = Flask(__name__)
app.secret_key = env_vars['FLASK_SECRET']
csrf = CSRFProtect(app)

AWS_ACCESS_KEY_ID = env_vars['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = env_vars['AWS_SECRET_ACCESS_KEY']
AWS_REGION = env_vars['AWS_REGION']
S3_BUCKET_NAME = env_vars['S3_BUCKET_NAME']
S3_FOLDER_NAME = env_vars['S3_FOLDER_NAME']
s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION)

conn = mysql.connector.connect(
    user=env_vars['DB_USER'],
    password=env_vars['DB_PASS'],
    host=env_vars['DB_HOST'],
    database=env_vars['DB_NAME']
)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    captcha = StringField('Captcha', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    captcha = StringField('Captcha', validators=[DataRequired()])

def generate_captcha():
    captcha_value = str(random.randint(100000, 999999))
    return captcha_value

def generate_images(captcha_value):
    width, height = 200, 50
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype('static/fonts/arial.ttf', 50)
    text_bbox = draw.textbbox((0, 0), captcha_value, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    x = (width - text_width) // 2
    y = (height - font.size) // 2
    draw.text((x, y), captcha_value, font=font, fill='black')
    image_io = io.BytesIO()
    image.save(image_io, 'PNG')
    image_io.seek(0)
    image_base64 = base64.b64encode(image_io.getvalue()).decode('utf-8')
    return image_base64

def str2md5(strg):
    return hashlib.md5(str(strg).encode()).hexdigest()

def sqlif(input_string):
    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'JOIN', 'UNION', 'INTO', 'FROM', 'WHERE', 'OR', 'AND']
    input_lower = input_string.lower()    
    for keyword in sql_keywords:
        if keyword.lower() in input_lower:
            input_string = re.sub(r'\b' + re.escape(keyword) + r'\b', '', input_string, flags=re.IGNORECASE)
    return input_string

@app.before_request
def before_req():
    whitelist = [
        '/login',
        '/register'
    ]
    if request.path not in whitelist and "/static" not in request.path and "username" not in session:
        return redirect('/login')

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return redirect(request.referrer)

@app.route('/')
def index():
    response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=S3_FOLDER_NAME)
    objects = response.get('Contents', [])
    file_names = [obj['Key'] for obj in objects if obj['Key'] != 'images/']
    return render_template('index.html', username=session["username"], file_names=file_names)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    try:
        if session["username"]:
            return redirect(url_for('index'))
    except:
        pass

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        captcha = form.captcha.data
        captcha_value = session['captcha_value']

        try:
            cursor = conn.cursor()
            safeusername = sqlif(username)
            query = "SELECT unam,hash,salt FROM creds WHERE unam = %s"
            cursor.execute(query, [safeusername])
            usrs, hash, salt = cursor.fetchone()
            md5pas = str2md5(password)
            md5salt = str2md5(salt)
            pasandsalt = '{}.{}'.format(md5pas, md5salt)
        except:
            captcha_value = generate_captcha()
            session['captcha_value'] = captcha_value
            error = 'Username, password, or captcha is incorrect'
            return render_template('login.html', form=form, error=error, captcha_value=generate_images(captcha_value))

        if username == usrs and bcrypt.checkpw(pasandsalt.encode('utf-8'), hash.encode('utf-8')) == True and captcha == captcha_value:
            session["username"] = username
            return redirect(url_for('index'))
        else:
            captcha_value = generate_captcha()
            session['captcha_value'] = captcha_value
            error = 'Username, password, or captcha is incorrect'
            return render_template('login.html', form=form, error=error, captcha_value=generate_images(captcha_value))

    else:
        captcha_value = generate_captcha()
        session['captcha_value'] = captcha_value
        return render_template('login.html', form=form, captcha_value=generate_images(captcha_value))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    try:
        if session["username"]:
            return redirect(url_for('index'))
    except:
        pass

    if form.validate_on_submit():
        firstname = sqlif(form.firstname.data)
        lastname = sqlif(form.lastname.data)
        username = sqlif(form.username.data)
        password = sqlif(form.password.data)
        captcha = form.captcha.data

        hashf = str2md5(password)
        salt = generate_captcha()
        saltf = str2md5(salt)
        adhash = "{}.{}".format(hashf, saltf)
        enhash = bcrypt.hashpw(adhash.encode('utf-8'), bcrypt.gensalt())
        ctim = time.time()

        try:
            cursor = conn.cursor()
            query = "SELECT unam FROM creds WHERE unam = %s"
            cursor.execute(query, [username])
            usrs = cursor.fetchone()
            if captcha == session['captcha_value'] and usrs == False:
                query = "INSERT INTO creds (fnam, lnam, unam, hash, salt, ctim, utim, rol) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                values = (firstname, lastname, username, enhash.decode(), salt, ctim, ctim, 1)
                cursor.execute(query, values)
                conn.commit()
                captcha_value = generate_captcha()
                session['captcha_value'] = captcha_value
                sucess = 'Successfully registered'
                return render_template('register.html', form=form, sucess=sucess, captcha_value=generate_images(captcha_value))
            else:
                captcha_value = generate_captcha()
                session['captcha_value'] = captcha_value
                error = 'Username exists or captcha is incorrect'
                return render_template('register.html', form=form, error=error, captcha_value=generate_images(captcha_value))
        except:
            captcha_value = generate_captcha()
            session['captcha_value'] = captcha_value
            error = 'Please fill in all fields correctly'
            return render_template('register.html', form=form, error=error, captcha_value=generate_images(captcha_value))
    else:
        captcha_value = generate_captcha()
        session['captcha_value'] = captcha_value
        return render_template('register.html', form=form, captcha_value=generate_images(captcha_value))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/galery')
def galery():
    response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME, Prefix=S3_FOLDER_NAME)
    objects = response.get('Contents', [])
    file_names = [obj['Key'] for obj in objects if obj['Key'] != 'images/']
    return render_template('galery.html', username=session["username"], file_names=file_names)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', use_reloader=True, port=8800)
