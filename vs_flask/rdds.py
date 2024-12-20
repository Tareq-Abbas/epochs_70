from flask import Flask, render_template,render_template_string, url_for, redirect, flash, get_flashed_messages, request,  session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, logout_user, UserMixin,  login_user, login_required
from flask_migrate import Migrate
from flask_modals_Markup.flask_modals.modal import render_template_modal, Modal
from flask_ckeditor import CKEditorField, CKEditor
import secrets
from PIL import Image
import os
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Message, Mail
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView
from flask_admin import expose
from flask import Markup
import cv2
import torch
import numpy as np
import json
from sqlalchemy import or_, and_, asc



app= Flask(__name__)
bcrypt= Bcrypt()
login_manager = LoginManager(app)
login_manager.login_view = 'login' # every page needs a login before going to it will use this
# which mean if the user is not loged in for such pages send him to the page 'login'


app.config['SECRET_KEY']= os.environ.get('SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///mydb1.db'

db= SQLAlchemy(app)
migrate = Migrate(app,db)
modal=Modal(app)
ckeditor= CKEditor(app)
app.config["MAIL_SERVER"] = "smtp.googlemail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PASS")
mail = Mail(app)







def frosted_glass_effect_with_boxes(img, boxes, blur_factor=15, transparency=0.2):
    """
    Applies a frosted glass effect to the image **outside** the detected boxes and
    returns both the original image with boxes and the image with frosted glass effect.

    Args:
        img: The input image as a NumPy array.
        boxes: A list of bounding boxes as NumPy arrays (xmin, ymin, xmax, ymax).
        blur_factor: The kernel size for Gaussian blur (adjust for blur strength).
        transparency: The transparency level of the frosted effect (0.0 - 1.0).

    Returns:
        The original image with boxes drawn, and the image with a frosted glass effect and boxes drawn.
    """

    # Create an empty mask to mark areas outside boxes
    mask = np.zeros_like(img[:, :, 0])

    # Process each box and remove them from the mask
    for box in boxes:
        x_min, y_min, x_max, y_max = box.astype(int)
        mask[y_min:y_max, x_min:x_max] = 255  # Set the region inside the box to 255

    # Convert to BGRA for alpha channel
    frosted_effect = cv2.cvtColor(img, cv2.COLOR_BGR2BGRA)

    # Blur the background outside the boxes
    background = cv2.GaussianBlur(img, (blur_factor, blur_factor), 0)

    # Ensure both background and frosted_effect have the same number of channels
    if background.shape[2] == 3:
        background = cv2.cvtColor(background, cv2.COLOR_BGR2BGRA)

    # Apply the frosted glass effect only outside the boxes
    outside_boxes = cv2.bitwise_not(mask)
    frosted_effect[outside_boxes > 0] = background[outside_boxes > 0]
    frosted_effect[:, :, 3] = transparency * 255  # Set alpha channel for transparency

    # Draw boxes on the original image
    img_with_boxes = img.copy()
    for box in boxes:
        x_min, y_min, x_max, y_max = box.astype(int)
        cv2.rectangle(img_with_boxes, (x_min, y_min), (x_max, y_max), (0, 255, 0), 2)

    # Draw boxes on the frosted glass effect image
    for box in boxes:
        x_min, y_min, x_max, y_max = box.astype(int)
        cv2.rectangle(frosted_effect, (x_min, y_min), (x_max, y_max), (0, 255, 0), 2)
    #the next return will return the main image with boxes and blured one with boxes
    #return img_with_boxes, frosted_effect
    return frosted_effect



@app.route('/')
def home():
    #damages= Damage.query.paginate(page=1, per_page=6)
    damages= Damage.query.all()
    #damages= Damage.query.paginate(page=1, per_page=18)
    damage_dicts = [{'damage_id': damage.id ,'latitude': damage.latitude, 'longitude': damage.longitude} for damage in damages]
    damages_json = json.dumps(damage_dicts)
    return render_template('home.html',damages=damages_json, title='home')

@app.route('/about')
def about():
    return render_template('about.html', title='about')



@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form= LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password ,form.password.data ):
            login_user(user, remember=form.remember.data)
            next_page= request.args.get('next')
            flash(f"login successfully for {form.email.data}",'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash(f"try again {form.email.data}",'danger')
    return render_template('login.html', title='Login Page', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(fname=form.fname.data,lname=form.lname.data, username=form.username.data,
                    is_company=form.company.data,email=form.email.data, password= hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f"account created succesfully for {form.username.data}", 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  title='Register Page', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/reset_password', methods=['POST','GET'])
def reset_request():
    #if the user is already logedin, no need to this form to change the password
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form= RequestResetForm()
    if form.validate_on_submit():
        user= User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash(f"if the entered email exists, you will recieve an email to change the password soon","info")
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if not user:
        flash("The token is invalid or expired", "warning")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash(f"Your password has been updated. You can now log in", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", title="Reset Password", form=form)

def save_picture(form_picture, path, output_size=None):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_name = random_hex + f_ext
    picture_path = os.path.join(app.root_path, path, picture_name)
    i = Image.open(form_picture)
    if output_size:
        i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name


def save_damage_picture(form_picture, path, output_size=None):
    random_hex = secrets.token_hex(8)
    picture_name = random_hex + '.jpg'
    picture_path = os.path.join(app.root_path, path, picture_name)
    cv2.imwrite(picture_path, form_picture)
    return picture_name


def get_previous_next_damage(damage):
    id = damage.id
    last_user = Damage.query.all()[-1]
    previous_damage = Damage.query.filter_by(id=id - 1).first() if id > 1 else None
    next_damage = Damage.query.filter_by(id=id + 1).first() if id < last_user.id  else None
    return previous_damage, next_damage



def delete_picture(picture_name, path):
    picture_path = os.path.join(app.root_path, path, picture_name)
    try:
        os.remove(picture_path)
    except:
        pass

#Serialization: is the process of converting an object into a format that can be stored or transmitted.
# user for: 1-Saving and loading user objects: When you create a new user profile in a web application, 
#the user's information is typically stored in a database. This involves serializing the user object 
#into a format that can be stored in the database. When you load a user profile, 
#the user's information is retrieved from the database, and the serialized data is
# deserialized back into a user object.

#2-Sending and receiving data over a network: When you make an HTTP request to a web server, 
#you typically send data in the request body. This data is often serialized into JSON or XML format 
#to make it easier for the server to interpret. The server then processes the request and sends back 
#a response, which may include serialized data in the response body.

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Web App Password Reset Request",
        sender="YOUR EMAIL",
        recipients=[user.email],
        body=f"""To reset your password, visit the following link:
        {url_for('reset_password', token=token, _external=True)}
        
        if you did not make this request, please ignore this email.""",
    )
    mail.send(msg)





#try damage_id
@app.route('/<int:damage_id>')
def damage(damage_id):
    damage=Damage.query.filter_by(id=damage_id).first()
    if damage:
        previous_damage, next_damage = get_previous_next_damage(damage)
    damage_id = damage.id if damage else None
    damage = Damage.query.get_or_404(damage_id)
    
    offer_dicts = [{'id': offer.id,'cost': offer.cost, 'working_days': offer.working_days} for offer in damage.offers]
    offers_json = json.dumps(offer_dicts)
    if not offer_dicts:
        return render_template(
        "damage.html",
        title='Damages',
        damage=damage,
        previous_damage=previous_damage,
        next_damage=next_damage,offers_json=offers_json,
        cost_ranges_counts = {},
        working_days_ranges_counts = {})

    # Determine ranges for costs and working days
    cost_min = min(offer['cost'] for offer in offer_dicts)
    cost_max = max(offer['cost'] for offer in offer_dicts)
    working_days_min = min(offer['working_days'] for offer in offer_dicts)
    working_days_max = max(offer['working_days'] for offer in offer_dicts)
    
    # Define the range size (e.g., 10)
    range_size = 10
    
    # Calculate the number of ranges
    num_cost_ranges = (cost_max - cost_min) // range_size + 1
    num_working_days_ranges = (working_days_max - working_days_min) // range_size + 1
    #print(num_cost_ranges)
    
    # Initialize dictionaries to store counts for each range
    cost_ranges_counts = {cost_min + i *num_cost_ranges : 0 for i in range(range_size)}
    #print(cost_ranges_counts)
    working_days_ranges_counts = {working_days_min + i * num_working_days_ranges: 0 for i in range(range_size)}
    
    # Count the number of offers falling within each range
    for offer in offer_dicts:
        for i in range(range_size):
            if cost_min + (i * num_cost_ranges) <= offer['cost'] < cost_min + ((i + 1) * num_cost_ranges):
                cost_ranges_counts[cost_min + i * num_cost_ranges] += 1
                break
        for i in range(range_size):
            if working_days_min + i * num_working_days_ranges <= offer['working_days'] < working_days_min + (i + 1) * num_working_days_ranges:
                working_days_ranges_counts[working_days_min + i * num_working_days_ranges] += 1
                break

    return render_template(
        "damage.html",
        title='Damages',
        damage=damage,
        previous_damage=previous_damage,
        next_damage=next_damage,
        offers_json=offers_json,cost_ranges_counts=cost_ranges_counts, 
        working_days_ranges_counts=working_days_ranges_counts
    )


#here we define the passed values are string ,so make sure to pass in html file an string values
@app.route('/<string:damage_address>/<string:offer_user>')
def offer(offer_user, damage_address):
    offers=Offer.query.all()
    offer_dicts = [{'cost': offer.cost, 'working_days': offer.working_days} for offer in offers]
    offers_json = json.dumps(offer_dicts)
    return render_template('offer.html', title='Offers', offers=offers_json)

@app.route('/dashboard')
@login_required
def dashboard():
    # when we go to the dashboard the first time we dont want any tab to be active so active_tab=None
    return render_template('dashboard.html' ,title='Dashboard', active_tab= None)


#now we need to finish allthe tabs in the dashboard

#1-Profile
@app.route("/dashboard/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_form = UpdateProfileForm()
    if profile_form.validate_on_submit():
        if profile_form.picture.data:
            delete_picture(current_user.image_file,'static/user_pics')
            picture_file = save_picture(profile_form.picture.data, 'static/user_pics', output_size=(150,150))
            current_user.image_file = picture_file
        current_user.username = profile_form.username.data
        current_user.email = profile_form.email.data
        db.session.commit()
        flash("Your profile has been updated", "success")
        return redirect(url_for("profile"))
    elif request.method == "GET":
        profile_form.username.data = current_user.username
        profile_form.email.data = current_user.email
    image_file = url_for("static", filename=f"user_pics/{current_user.image_file}")
    return render_template(
        "profile.html",
        title="Profile",
        profile_form=profile_form,
        image_file=image_file,
        active_tab="profile",
    )

#2-new_damage
@app.route("/dashboard/new_damage", methods=["GET", "POST"])
@login_required
def new_damage():
    form = NewDamageForm()
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')
    address_loc = request.args.get('address_loc')# address location

    if form.validate_on_submit() :
        if form.picture.data:

            # Load the model
            #model = torch.hub.load('ultralytics/yolov5', 'custom', 'ultralytics/yolov5/best.pt')
            model = torch.hub.load('ultralytics/yolov9-main', 'custom', source="local",  path='best7.pt')
            img = cv2.imread(form.picture.data)
            results = model(img)
            info = results.pandas().xyxy[0]
            object_boxes = info[info['name'].isin(['D00','D10','D20','D40'])][['xmin', 'ymin', 'xmax', 'ymax']].to_numpy()
            frosted_effect_with_boxes = frosted_glass_effect_with_boxes(img, object_boxes)
            objects = ''
            for name in info["name"]:
                objects += name + ' '
            if (objects != ''):
                form.type.data= objects
            else:
                form.type.data= 'type is not detected'
            picture_file= save_damage_picture(frosted_effect_with_boxes, 'static/damage_images')
        
        damage_address = address_loc #str(form.address.data)# we use replace to change every ' ' in the thug to '-' because useing ' ' in the url will lead to many unwanted letters such §$% in the url
        if not (Damage.query.filter_by(address=damage_address).first()): # to check if the address exists
            damage = Damage(
                type=form.type.data,
                latitude=form.latitude.data,
                longitude=form.longitude.data,
                address=form.address.data,
                applier=current_user,
                image_file= picture_file,
            )
            db.session.add(damage)
            db.session.commit()
            flash("Your damage has been created!", "success")
            return redirect(url_for("new_damage"))
        else:
            flash("Your damage has been added before!", "danger")

    return render_template(
        "new_damage.html", #............. the name we want to render
        title="New Damage",
        form=form,
        active_tab="new_damage",
        longitude=longitude,
        latitude=latitude,
        address_loc=address_loc

    )

#3- user_damages:this describe the layout of the damage
# when we click on update we will go to damage_update form, 
#when we click on delete we will go to delete form, when we click on damage we will go to damage.html
@app.route("/dashboard/user_damages", methods=["GET", "POST"])
@login_required
def user_damages():
    #here we do not need to pass damages=damages in render_template because in the html file
    #we can get it using current_user.damages
    # for damage in current_user.damage {{damage}}
    return render_template("user_damages.html", title="Your Damages", active_tab="user_damages")

# inside the user_damages each damage has 3 buttons update_damage, new_offer, delete_damage
@app.route('/<int:damage_id>/update', methods=['GET', 'POST'])
def update_damage(damage_id):
    damage=Damage.query.filter_by(id=damage_id).first()
    if damage:
        previous_damage, next_damage= get_previous_next_damage(damage)
    damage_id = damage.id if damage else None
    
    damage = Damage.query.get_or_404(damage_id)
    if damage.applier != current_user:
        abort(403)
    form = UpdateDamageForm()
    if form.validate_on_submit():
        #damage.state = form.state.data
        damage.address = form.address.data
        #damage.description = str(form.description.data).replace(" ", "-")
        if form.picture.data:
            # Load the model
            #model = torch.hub.load('ultralytics/yolov5', 'custom', 'ultralytics/yolov5/best.pt')
            model = torch.hub.load('ultralytics/yolov9-main', 'custom', source="local",  path='best7.pt')
            img = cv2.imread(form.picture.data)
            results = model(img)
            info = results.pandas().xyxy[0]
            object_boxes = info[info['name'].isin(['D00','D10','D20','D40'])][['xmin', 'ymin', 'xmax', 'ymax']].to_numpy()
            frosted_effect_with_boxes = frosted_glass_effect_with_boxes(img, object_boxes)
            objects = ''
            for name in info["name"]:
                objects += name + ' '
            if (objects != ''):
                damage.type= objects
            else:
                damage.type= 'type is not detected'
            delete_picture(damage.image_file, "static/damage_images")
            new_picture = save_damage_picture(frosted_effect_with_boxes, "static/damage_images")
            damage.image_file = new_picture
        db.session.commit()
        flash("Your damage has been updated!", "success")
        return redirect(
            url_for("damage", damage_id=damage.id)
        )
    elif request.method == "GET":
        form.latitude.data = damage.latitude
        form.longitude.data = damage.longitude
        form.address.data = damage.address
        #form.description.data = damage.description
    else:
        # Invalid form data, display errors
        for field_name,error in form.errors.items():
            flash(f'{error} is required. The error in the field {field_name}')
        return render_template('update_damage.html', title="Update | " + str(damage.id),
        damage=damage,
        previous_damage=previous_damage,
        next_damage=next_damage,
        form=form)
    return render_template(
        "update_damage.html",
        title="Update | " + str(damage.id),
        form=form,
        damage=damage,
        previous_damage=previous_damage,
        next_damage=next_damage,
        
    )

# in the user_damages tab we need 2 routes to handle delet damages and update damages
@app.route("/damage/delete/<int:damage_id>", methods=["GET","POST"])
def delete_damage(damage_id):
    damage = Damage.query.get_or_404(damage_id)
    if damage.applier != current_user:
        abort(403)
    damage=Damage.query.filter_by(id=damage_id).first()
    offers=damage.offers
    #print(offers)
    if offers:
        for offer in offers:
            db.session.delete(offer)
            db.session.commit()
    #print(damage_id)
    #print(damage.id)
    delete_picture(damage.image_file, "static/damage_images")
    db.session.delete(damage)
    db.session.commit()
    
    flash("Your damage has been deleted!", "success")
    return redirect(url_for("user_damages"))

@app.route("/dashboard/<damage_id>/new_offer", methods=["GET", "POST"])
@login_required
def new_offer(damage_id):
    damage=Damage.query.filter_by(id=damage_id).first()
    if damage:
        form = NewOfferForm()

        if form.validate_on_submit():
            offer = Offer(working_days=form.working_days.data,cost=form.cost.data,
                        company=current_user,applications=damage)
            db.session.add(offer)
            db.session.commit()
            flash("Your Offer has been created!", "success")
            return redirect(url_for("dashboard"))


    return render_template(
        "new_offer.html",
        title="New Offer",
        form=form,
        damage_id=damage.id,
        active_tab="new_offer"
    )
#4- in the dashboard we have user_offers
@app.route("/dashboard/user_offers", methods=["GET", "POST"])
@login_required
def user_offers():
    page = request.args.get("page", 1, type=int)#for pagination
    #damages = Damage.query.paginate(page=page, per_page=2)# for pagination
    per_page = request.args.get('per_page', 10, type=int)

    user_id = current_user.id

    # Step 1: Create the base query
    base_query = Damage.query.filter(~Damage.offers.any(use_id=user_id))

    # Step 2: Paginate the query
    pagination = base_query.paginate(page=page, per_page=per_page, error_out=False)

    # Retrieve the actual damages from the pagination object
    damages = pagination.items
    return render_template("user_offers.html", title="Your Offers",damages=damages, pagination=pagination, active_tab="user_offers")

#each offer has 2 buttons delete_offer and update_offer

# in the user_offers tab we need 2 routes to handle delet offers and update offers
@app.route("/offer/delete/<int:offer_id>", methods=["GET","POST"])
def delete_offer(offer_id):
    offer = Offer.query.get_or_404(offer_id)
    print(offer)
    if offer.company != current_user:
        abort(403)
    db.session.delete(offer)
    db.session.commit()
    
    flash("Your offer has been deleted!", "success")
    return redirect(url_for("user_offers"))


@app.route('/dashboard/update/<int:offer_id>', methods=["GET", "POST"])
def update_offer(offer_id):
    offer = Offer.query.get_or_404(offer_id)
    if offer.company != current_user:
        abort(403)
    form = UpdateOfferForm()
    if form.validate_on_submit():
        offer.working_days = form.working_days.data
        offer.cost = form.cost.data
        db.session.commit()
        flash("Your offer has been updated!", "success")
        return redirect(
            url_for("user_damages")
        )
    elif request.method == "GET":
        form.working_days.data = offer.working_days
        form.cost.data = offer.cost
    return render_template(
        "update_offer.html",
        title="Update | " + str(offer.id),
        form=form,
        offer=offer)

@app.route("/user_page/<string:username>", methods=["GET"])
def user_page(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    damages = (
        Damage.query.filter_by(applier=user)
        .paginate(page=page, per_page=6)
    )
    return render_template('user_page.html', damages=damages, user=user)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))


class User(db.Model, UserMixin):
    id= db.Column(db.Integer, primary_key=True)
    fname= db.Column(db.String(26), nullable=False)
    lname=db.Column(db.String(26), nullable=False)
    username= db.Column(db.String(26), unique=True, nullable=False)
    email= db.Column(db.String(126),unique=True,nullable=False)
    is_company=db.Column(db.Boolean, default=False)
    image_file = db.Column(db.String(26), nullable= False, default='default.png')
    password=db.Column(db.String(60),nullable=False)
    offers = db.relationship('Offer', backref='company',cascade="all, delete-orphan", lazy=True)
    damages = db.relationship('Damage', backref='applier',cascade="all, delete-orphan", lazy=True)

    def get_reset_token(self):
        #This line of code creates a Serializer object from the app.config['SECRET_KEY'] and 'pw-reset'
        s = Serializer(app.config['SECRET_KEY'], salt='pw-reset')
        #This line of code encodes the user's ID into a token. 
        #The token is encoded using the dumps() method of the Serializer object. 
        #The token is a JSON object with the key 'user_id' and the value of the user's ID (self.id).
        return s.dumps({'user_id': self.id})


    @staticmethod
    def verify_reset_token(token, age=3600):
        #here we create a serialize object to decode the token
        s = Serializer(app.config['SECRET_KEY'], salt='pw-reset')
        try:
            #This line of code attempts to decode the token. 
            #The loads() method of the Serializer object decodes the token into a JSON object. 
            #If the token is valid, the 'user_id' key will be present in the JSON object.
            user_id = s.loads(token, max_age=age)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.fname}, {self.lname}, {self.username}, {self.email}')"
    

class Damage(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    type= db.Column(db.String(26), nullable=False)
    latitude=db.Column(db.Float(26))
    longitude=db.Column(db.Float(26))
    address= db.Column(db.String(126), unique=True, nullable=False)
    image_file=db.Column(db.String(26), nullable=False, default='default.png')
    use_id=db.Column(db.Integer, db.ForeignKey("user.id"),nullable=False)
    offers= db.relationship('Offer', backref='applications',cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"Damage('{self.type}, {self.address}')"
    
class Offer(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    working_days= db.Column(db.Integer, nullable=False)
    cost= db.Column(db.Integer, nullable=False)
    use_id= db.Column(db.Integer, db.ForeignKey("user.id"),nullable=False)
    damage_id= db.Column(db.Integer, db.ForeignKey("damage.id"),nullable=False)

    def __repr__(self):
        return f"Offer('{self.working_days}, {self.cost}')"




from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField,IntegerField,FloatField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from wtforms_sqlalchemy.fields import QuerySelectField




class RegistrationForm(FlaskForm):
    fname= StringField('First Name', validators=[DataRequired(), Length(min=2, max=26)])
    lname= StringField('Last Name', validators=[DataRequired(), Length(min=2, max=26)])
    username=StringField('User Name', validators=[DataRequired(), Length(min=2, max=26)])
    email=StringField('Email', validators=[DataRequired(), Email()])
    password=PasswordField('Password', validators=[DataRequired(), Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$")])
    confirm_password= PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password')])
    company=BooleanField('Company?')
    submit=SubmitField('Submit')


    #https://stackabuse.com/flask-form-validation-with-flask-wtf/
    #Creating Your Own Custom Validators
    #adding a validation method
    #def validate_FieldName(self, FieldName)
        #some condition 
            #raise ValidationError(Validation Message)
    #When you want to capture the error in html file we use {{ form.some_field.data }}

    # PS: IMPORTANT 
    #WTForms will run validation methods automatically once defined.

    def validate_username(self, username):
        user= User.query.filter_by(username= username.data).first()
        if user:
            raise ValidationError('This Username is already existed')
        

    def validate_email(self, email):
        user= User.query.filter_by(email= email.data).first()
        if user:
            raise ValidationError('This Email is already existed')

class UpdateProfileForm(FlaskForm):
    username= StringField('User Name', validators=[DataRequired()])
    email= StringField('Email', validators=[DataRequired(), Email()])
    biography= TextAreaField('Biography')
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['png', 'jpg'])])
    submit=SubmitField('Submit')


    def validate_username(self, username):
        # if the user wanted to change only the profile image, we will get an error when 
        # the user clicks submit because the username is already existed, so to avoid this 
        # we add a condition to check the username only if the username.data (entered to the form)
        #  is different from the current_user.username
        if username.data != current_user.username:
            user= User.query.filter_by(username= username.data).first()
            if user:
                raise ValidationError('This Username is already existed')
        

    def validate_email(self, email):
        if email.data != current_user.email:
            user= User.query.filter_by(email= email.data).first()
            if user:
                raise ValidationError('This Email is already existed')


class LoginForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(),Email()])
    password=PasswordField('Password', validators=[DataRequired()])
    remember=BooleanField('Remember Me?')
    submit=SubmitField('Submit')

class NewDamageForm(FlaskForm):
    type=StringField('Type', validators=[DataRequired()])
    latitude=FloatField('latitude')
    longitude=FloatField('longitude')
    address=StringField('House Number, Street, City, Postal Code, Country', validators=[DataRequired()])
    picture = FileField('Damage Picture', validators=[DataRequired(),FileAllowed(['png', 'jpg'])])
    submit=SubmitField('Submit')


class NewOfferForm(FlaskForm):
    working_days=IntegerField('Working Days', validators=[DataRequired()])
    cost=IntegerField('Cost',validators=[DataRequired()])
    submit=SubmitField('Submit')


class UpdateDamageForm(NewDamageForm):
    type=StringField('Type', validators=[])# we add this to avoid error when submitting because it is requiered in the father form
    #state=StringField('State', validators=[])
    #address=StringField('City, Street, House Number', validators=[])
    description=CKEditorField("Description", validators=[], render_kw={"rows": "20"})
    picture = FileField('Damage Picture:', validators=[FileAllowed(['png', 'jpg'])])
    submit=SubmitField('Update')


class UpdateOfferForm(FlaskForm):
    working_days=IntegerField('Working Days', validators=[DataRequired()])
    cost=IntegerField('Cost',validators=[DataRequired()])
    submit=SubmitField('Update')



class RequestResetForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(), Email()])
    submit= SubmitField('Request Paswword Reset')

    #make sure the email iserteed in the EmailField is already in the DB
    def validate_email(self,email):
        user=User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no such Email')


class ResetPasswordForm(FlaskForm):
    password=PasswordField('Passowrd', validators=[DataRequired(),Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_])[A-Za-z\d@$!%*?&_]{8,32}$")])
    confirm_passowrd= PasswordField('Confirm Passowd', validators=[DataRequired(), EqualTo('password')])
    submit=SubmitField('Reset Passowrd')









class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.id == 1


class MyModelView(ModelView):

    def on_model_change(self, form, model, is_created):
        model.password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8)"
        )

    column_searchable_list = ('id', 'email', 'username') 
    def is_accessible(self):
        return current_user.is_authenticated and current_user.id == 1
    
    def on_model_delete(self, model):
        # Assuming 'current_user' is your logged-in admin user
        if model.id == current_user.id:
            flash('You cannot delete your own account.', 'error')
            return redirect(url_for('admin.index')) 
    
    
    

class DamageModelView(ModelView):

    column_searchable_list = ('type', 'address')  # Include address here

    # show specific columns
    column_list = ('id','type','latitude','longitude','address','image_file', 'use_id', 'view_offers')

    

    def _view_offers_formatter(view, context, model, name):
        # Check if there are offers for the given damage_id (which is the same as product_id)
        offers_exist = view.session.query(Offer).filter_by(damage_id=model.id).count() > 0

        if offers_exist:
            # Render an active button if offers exist
            return Markup('<a class="btn btn-primary" href="{}">View Offers</a>'.format(
                url_for('offer.index_view', damage_id=model.id)
            ))
        else:
            # Render a disabled button if no offers exist
            return Markup('<button class="btn btn-secondary" disabled>No Offers</button>')

    # Register the custom formatter
    column_formatters = {
        'view_offers': _view_offers_formatter
    }


    # show the records of each column
    form_columns =('id','type','latitude','longitude','address','image_file', 'use_id')
    
class OfferModelView(ModelView):


    # Store the damage ID for filtering
    _damage_id = None
    #will be sorted according to the first column name mentioned here (id, true)
    column_default_sort = [('id', True), ('working_days', True),('cost', True)]

    # we add , after damage_id because it does not accept search for only one thing so we add , to avoid the error
    column_searchable_list = ('cost','working_days')  # Include address here

    # show specific columns
    column_list = ('id','working_days', 'cost', 'use_id', 'damage_id')


    def get_query(self):
        """Handle filtering by damage_id for inline views and handle search."""
        # Start with the base query
        query = self.session.query(self.model)
        
        # Get the damage_id (damage_id) from the URL if navigating from damageViewModel
        damage_id = request.args.get('damage_id')
        
        # Apply damage_id (damage_id) filtering if available (inline view case)
        if damage_id:
            query = query.filter_by(damage_id=damage_id)
        
        # Handle the search functionality if a search term is provided (both inline and general view)
        search_term = request.args.get('search', None)
        
        
        if search_term:
            search_parts = search_term.split()

            
            '''search_filter = or_(
            self.model.cost.ilike(f'%{search_term}%'),
            self.model.working_days.ilike(f'%{search_term}%')
            )
            query = query.filter(search_filter)'''
            #print("Filtered Query Results:", query)
            try:
                search_filter = or_(
                self.model.cost.ilike(f'%{search_term}%'),
                self.model.working_days.ilike(f'%{search_term}%')
                )
                query = query.filter(search_filter)
            except ValueError:
                query
        
        # Return the query, ordering by cost
        return query

    # show the records of each column
    form_columns =('id','working_days', 'cost', 'use_id', 'damage_id')
    
    

admin = Admin(app, index_view=MyAdminIndexView(), template_mode='bootstrap3')

admin.add_view(MyModelView(User, db.session))
admin.add_view(DamageModelView(Damage, db.session))
admin.add_view(OfferModelView(Offer, db.session))


if __name__=='__main__':
    app.run(debug=True)



# export EMAIL_PASS="iuzpbayifmamuzlx"
# export EMAIL_USER="nagem2.dergham@gmail.com"
