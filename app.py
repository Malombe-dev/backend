from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
import mysql.connector
from flask_cors import CORS, cross_origin
import os
from werkzeug.utils import secure_filename
from models import Product, db
from flask_socketio import SocketIO
from flask import request, jsonify
from werkzeug.security import generate_password_hash
from datetime import datetime
import re



app = Flask(__name__)


app.secret_key = "your_secret_key"  # 🔹 Change this to a strong secret key
bcrypt = Bcrypt(app)

# 🔹 Adjust Session Configuration for Cross-Origin
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # ✅ Good for PythonAnywhere HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # ✅ Enables cross-origin cookie for React + Flask


import os

# CORS origins - read from environment variable or fallback to defaults
cors_origins = os.getenv("CORS_ORIGINS", 
    "http://localhost:3000,"
    "https://the-market-place-sigma.vercel.app,"
    "https://marketplace-alpha-one.vercel.app,"
    "https://vmalombe.pythonanywhere.com"
).split(",")

CORS(app, supports_credentials=True, origins=cors_origins)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")  # Set in Railway vars
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socketio = SocketIO(app, cors_allowed_origins=cors_origins)

db.init_app(app)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )


# 🔹 Handle all OPTIONS preflight requests globally
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return '', 200

# 🔹 Debug Route to Check Session
@app.route('/debug-session', methods=['GET'])
def debug_session():
    return jsonify({
        "session": dict(session),
        "logged_in": "user_id" in session
    }), 200


# sign up




@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    required_fields = ['name', 'email', 'phone', 'dob', 'location', 'password']
    for field in required_fields:
        if field not in data or not data[field].strip():
            return jsonify({"error": f"{field} is required"}), 400

    name = data['name'].strip()
    email = data['email'].strip().lower()
    phone = data['phone'].strip()
    dob_str = data['dob'].strip()
    location = data['location'].strip()
    password = data['password']

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400

    try:
        dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "Date of birth must be YYYY-MM-DD"}), 400

    # ✅ Use flask_bcrypt to hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already registered"}), 409

        cursor.execute(
            """
            INSERT INTO users (name, email, phone, dob, location, password, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
            (name, email, phone, dob, location, hashed_password)
        )
        conn.commit()
        user_id = cursor.lastrowid

        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201

    except Exception as e:
        print("Signup error:", e)
        return jsonify({"error": "Internal server error"}), 500

    finally:
        cursor.close()
        conn.close()


# 🔹 Login Route (Creates a Session)
@app.route('/login', methods=['POST', 'OPTIONS'])
@cross_origin(supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid email or password"}), 401

    # 🔹 Set session
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    print("Session after login:", session)

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email']
        }
    }), 200

# 🔹 Logout Route (Clears Session)
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

# 🔹 Check Session Route (Verifies if User is Logged In)
@app.route('/check-session', methods=['GET'])
def check_session():
    print("Session in check-session:", session)
    if 'user_id' in session:
        return jsonify({
            "logged_in": True,
            "user": {
                "id": session['user_id'],
                "name": session['user_name']
            }
        }), 200
    return jsonify({"logged_in": False}), 401

    # profile

@app.route('/profile', methods=['GET'])
def profile():
    print("Session in profile:", session)

    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch user details
        cursor.execute("SELECT id, name, email, phone, dob, location, profile_photo FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Ensure full profile photo URL
        if user["profile_photo"] and not user["profile_photo"].startswith("http"):
            user["profile_photo"] = f"https://vmalombe.pythonanywhere.com/{user['profile_photo']}"

        # Fetch user's products
        cursor.execute("SELECT id, product_name, category, price, location, front_photo FROM product WHERE user_id = %s", (user_id,))
        products = cursor.fetchall()

        # Ensure full image URL for product photos
        for product in products:
            if product["front_photo"] and not product["front_photo"].startswith("http"):
                product["front_photo"] = f"https://vmalombe.pythonanywhere.com/{product['front_photo']}"

        # Fetch user skills
        cursor.execute("SELECT id, title, description, location, phone FROM skills WHERE user_id = %s", (user_id,))
        skills = cursor.fetchall()

        return jsonify({"user": user, "posts": products, "skills": skills})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()  # Ensure connection is closed no matter what



    # delete post
@app.route('/delete-post/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure the post belongs to the logged-in user
    cursor.execute("SELECT id FROM product WHERE id = %s AND user_id = %s", (post_id, user_id))
    post = cursor.fetchone()

    if not post:
        conn.close()
        return jsonify({"error": "Post not found or unauthorized"}), 404

    # Delete the post
    cursor.execute("DELETE FROM product WHERE id = %s", (post_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Post deleted successfully"}), 200



# 🔹 Define Upload Folder
PRODUCT_UPLOAD_FOLDER = '/home/vmalombe/mysite/static/uploads'
app.config['PRODUCT_UPLOAD_FOLDER'] = PRODUCT_UPLOAD_FOLDER

# 🔹 Ensure upload directory exists
os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload_product', methods=['POST'])
def upload_product():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized: Please log in to upload a product."}), 401

    data = request.form
    files = request.files

    required_fields = ["product_name", "category", "description", "price", "location", "age"]
    required_photos = ["image_front", "image_back", "image_side1", "image_side2"]

    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"{field} is required"}), 400

    for photo in required_photos:
        if photo not in files or files[photo].filename == '':
            return jsonify({"error": f"{photo} is required"}), 400

    photo_paths = {}
    for photo in required_photos:
        file = files[photo]
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename)

        try:
            file.save(file_path)
        except Exception as e:
            return jsonify({"error": f"Failed to save {photo}: {str(e)}"}), 500

        # 🔹 Store relative path (for serving via static files)
        photo_paths[photo] = f"static/uploads/{filename}"

    new_product = Product(
        user_id=session["user_id"],
        product_name=data["product_name"],
        category=data["category"],
        description=data["description"],
        price=float(data["price"]),
        location=data["location"],
        age=data["age"],
        notes=data.get("notes", ""),
        front_photo=photo_paths["image_front"],
        back_photo=photo_paths["image_back"],
        side_photo_1=photo_paths["image_side1"],
        side_photo_2=photo_paths["image_side2"],
        contact=session["user_name"]
    )

    try:
        db.session.add(new_product)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    return jsonify({"message": "Product uploaded successfully"}), 201



# 🔹 Skill Upload Route (POST)
@app.route('/upload-skill', methods=['POST'])
def upload_skill():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    user_id = session['user_id']
    title = data.get('title')
    description = data.get('description')
    location = data.get('location')
    phone = data.get('phone')

    if not title or not description or not location or not phone:
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO skills (user_id, title, description, location, phone)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, title, description, location, phone))

        conn.commit()
        return jsonify({"message": "Skill uploaded successfully"}), 201

    except mysql.connector.Error as err:
        print("Database error:", err)
        return jsonify({"error": "Database error"}), 500

    finally:
        cursor.close()
        conn.close()

# gett skills
@app.route('/skills', methods=['GET'])
def get_skills():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT id, title, description, location, phone FROM skills")
        skills = cursor.fetchall()
        return jsonify(skills), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Get all the products
@app.route('/products', methods=['GET'])
def get_products():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
                        SELECT
                            p.id, p.user_id, p.product_name, p.category, p.front_photo, p.back_photo,
                            p.side_photo_1, p.side_photo_2, p.location, p.description,
                            p.price, p.contact, p.created_at,
                            COALESCE(u.name, 'Unknown') AS posted_by
                        FROM product p
                        LEFT JOIN users u ON p.user_id = u.id
                    """)

        products = cursor.fetchall()

        base_url = "https://vmalombe.pythonanywhere.com/"
        default_image = "https://via.placeholder.com/150"

        for product in products:
            for key in ['front_photo', 'back_photo', 'side_photo_1', 'side_photo_2']:
                if product.get(key):
                    product[key] = f"{base_url}{product[key].lstrip('/')}"
                else:
                    product[key] = default_image

        return jsonify(products), 200
    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({"error": "An error occurred while fetching products"}), 500
    finally:
        cursor.close()
        conn.close()




@app.route('/product/<int:product_id>', methods=['GET'])
def get_product_details(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        print(f"Fetching product with ID: {product_id}")  # Debugging log

        # Fetch product details and user info
        cursor.execute("""
            SELECT p.id, p.user_id, p.product_name, p.category, p.description, p.price,
                   p.location, p.age, p.notes, p.front_photo, p.back_photo,
                   p.side_photo_1, p.side_photo_2, p.created_at,
                   COALESCE(u.name, 'Unknown') AS posted_by,
                   COALESCE(u.email, 'No email provided') AS contact_email,
                   COALESCE(u.phone, 'No phone provided') AS contact_phone,
                   COALESCE(u.profile_photo, '') AS profile_photo

            FROM product p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = %s
        """, (product_id,))

        product = cursor.fetchone()

        if not product:
            return jsonify({"error": "Product not found"}), 404

        # Ensure full URLs for images, add default placeholders if missing
        base_url = "https://vmalombe.pythonanywhere.com/"
        default_image = "https://via.placeholder.com/150"
        image_fields = ["front_photo", "back_photo", "side_photo_1", "side_photo_2", "profile_photo"]

        for key in image_fields:
            if product.get(key) and not product[key].startswith("http"):
                product[key] = f"{base_url}{product[key]}"
            elif not product.get(key):
                product[key] = default_image  # Default placeholder

        # Fetch related products (same category, exclude current product)
        related_products = []
        if product.get("category"):
            cursor.execute("""
                SELECT id, product_name, front_photo
                FROM product
                WHERE category = %s AND id != %s
                ORDER BY created_at DESC
                LIMIT 4
            """, (product["category"], product_id))

            related_products = cursor.fetchall()

            # Process related products images
            for related in related_products:
                if related.get("front_photo") and not related["front_photo"].startswith("http"):
                    related["front_photo"] = f"{base_url}{related['front_photo']}"
                elif not related.get("front_photo"):
                    related["front_photo"] = default_image  # Default placeholder

        return jsonify({
            "product": product,
            "related": related_products
        }), 200

    except Exception as e:
        print("ERROR:", str(e))  # Log error
        return jsonify({"error": "An error occurred while fetching product details"}), 500

    finally:
        cursor.close()
        conn.close()


        # profile photo



# 🔹 Profile Photo Upload Configuration
UPLOAD_FOLDER = '/home/vmalombe/mysite/static/profile_photos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 🔹 Ensure Upload Directory Exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 🔹 Helper Function to Check Allowed File Types
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# 🔹 Profile Photo Upload Route
@app.route('/upload-profile-photo', methods=['POST'])
def upload_profile_photo():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized: Please log in to upload a profile photo."}), 401

    if 'profile_photo' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['profile_photo']
    user_id = session['user_id']  # Get user ID from session

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        # Secure filename and save
        filename = secure_filename(f"user_{user_id}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Save profile photo path in database
        profile_photo_url = f"static/profile_photos/{filename}"
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE users SET profile_photo = %s WHERE id = %s", (profile_photo_url, user_id))
            conn.commit()
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

        return jsonify({
            "message": "Profile photo uploaded successfully",
            "profile_photo_url": f"https://vmalombe.pythonanywhere.com/{profile_photo_url}"
        }), 200

    return jsonify({"error": "Invalid file type"}), 400



# IA

@app.route('/homepage-data', methods=['GET'])
def homepage_data():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch user location
        cursor.execute("SELECT location FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        user_location = user.get('location')

        # Fetch recent user products
        cursor.execute("""
            SELECT id, product_name, front_photo
            FROM product
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 5
        """, (user_id,))
        recent_products = cursor.fetchall()

        # Initialize local products list
        local_products = []

        # Fetch products from the same location (excluding own products)
        if user_location:
            cursor.execute("""
                SELECT id, product_name, front_photo
                FROM product
                WHERE location = %s AND user_id != %s
                ORDER BY created_at DESC
                LIMIT 5
            """, (user_location, user_id))
            local_products = cursor.fetchall()

        base_url = "https://vmalombe.pythonanywhere.com/"
        default_image = "https://via.placeholder.com/150"

        def process_photos(products):
            for product in products:
                if product.get("front_photo"):
                    if not product["front_photo"].startswith("http"):
                        product["front_photo"] = f"{base_url}{product['front_photo'].lstrip('/')}"
                else:
                    product["front_photo"] = default_image
            return products

        return jsonify({
            "recent_user_products": process_photos(recent_products),
            "local_products": process_photos(local_products)
        })

    except Exception as e:
        print(f"Error in /homepage-data: {e}")  # Good for debugging logs
        return jsonify({
            "error": "Something went wrong. Please try again later.",
            "recent_user_products": [],
            "local_products": []
        }), 500

    finally:
        cursor.close()
        conn.close()



@app.route("/categories", methods=["GET"])
def get_categories():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT DISTINCT category FROM product")
        categories = [row['category'] for row in cursor.fetchall()]
        return jsonify(categories)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()





@app.route('/messages/threads/<int:user_id>', methods=['GET'])
def get_message_threads(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT m.*,
               sender.name AS sender_name,
               receiver.name AS receiver_name
        FROM messages m
        JOIN users sender ON m.sender_id = sender.id
        JOIN users receiver ON m.receiver_id = receiver.id
        INNER JOIN (
            SELECT
                CASE
                    WHEN sender_id = %s THEN receiver_id
                    ELSE sender_id
                END AS other_user_id,
                MAX(created_at) AS latest_time
            FROM messages
            WHERE sender_id = %s OR receiver_id = %s
            GROUP BY other_user_id
        ) latest
        ON ((m.sender_id = %s AND m.receiver_id = latest.other_user_id)
            OR (m.sender_id = latest.other_user_id AND m.receiver_id = %s))
           AND m.created_at = latest.latest_time
        ORDER BY m.created_at DESC
    """, (user_id, user_id, user_id, user_id, user_id))

    threads = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"threads": threads})





# @app.route('/messages/received/<int:user_id>', methods=['GET'])
# def get_received_messages(user_id):
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)

#     cursor.execute("""
#         SELECT m.*, u1.name AS sender_name
#         FROM messages m
#         JOIN users u1 ON m.sender_id = u1.id
#         WHERE m.receiver_id = %s
#         ORDER BY m.created_at DESC
#     """, (user_id,))

#     messages = cursor.fetchall()
#     cursor.close()
#     conn.close()

#     return jsonify({"messages": messages})

from datetime import datetime

@app.route('/messages/send', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message_text')

    if not all([sender_id, receiver_id, message_text]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, message_text, is_read, created_at)
        VALUES (%s, %s, %s, %s, NOW())
    """, (sender_id, receiver_id, message_text, 0))
    conn.commit()

    cursor.execute("SELECT * FROM messages WHERE id = LAST_INSERT_ID()")
    new_message = cursor.fetchone()

    cursor.close()
    conn.close()

    # Convert datetime fields to string before emitting
    if new_message and isinstance(new_message.get("created_at"), datetime):
        new_message["created_at"] = new_message["created_at"].isoformat()

    # Emit real-time event to the receiver's room
    socketio.emit("new_message", new_message, room=f"user_{receiver_id}")

    return jsonify({"success": True, "message": "Message sent successfully", "data": new_message}), 201



@app.route('/messages/conversation/<int:user1_id>/<int:user2_id>', methods=['GET'])
def get_conversation(user1_id, user2_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT m.*,
               sender.name AS sender_name,
               receiver.name AS receiver_name
        FROM messages m
        JOIN users sender ON m.sender_id = sender.id
        JOIN users receiver ON m.receiver_id = receiver.id
        WHERE (m.sender_id = %s AND m.receiver_id = %s)
           OR (m.sender_id = %s AND m.receiver_id = %s)
        ORDER BY m.created_at ASC
    """, (user1_id, user2_id, user2_id, user1_id))

    messages = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({"messages": messages})




@app.route('/message/unread-count/<int:user_id>', methods=['GET'])
def get_unread_count(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT COUNT(*) AS unread_count
        FROM messages
        WHERE receiver_id = %s AND is_read = 0
    """, (user_id,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return jsonify({"unread_count": result["unread_count"]})





@app.route('/messages/mark-read/<int:message_id>', methods=['POST'])
def mark_message_as_read(message_id):
    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE messages
        SET is_read = 1
        WHERE id = %s AND receiver_id = %s
    """, (message_id, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "Message marked as read"})



# ?meesaging
@app.route('/message', methods=['POST'])
def send_message1():
    data = request.get_json()
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message_text')

    if not sender_id or not receiver_id or not message_text:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO messages (sender_id, receiver_id, message_text)
        VALUES (%s, %s, %s)
    """, (sender_id, receiver_id, message_text))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "Message sent"}), 201




@app.route('/messages/delete/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    message = Message.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()
        return jsonify({"status": "deleted"}), 200
    return jsonify({"error": "Message not found"}), 404

