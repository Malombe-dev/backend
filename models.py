from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Product(db.Model):
    __tablename__ = 'product'  # Ensure it matches your table name

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_name = db.Column(db.String(255), nullable=False)  # ✅ Matches database column
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)  # ✅ Matches decimal(10,2)
    location = db.Column(db.String(255), nullable=False)
    age = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    front_photo = db.Column(db.String(255), nullable=False)
    back_photo = db.Column(db.String(255), nullable=False)
    side_photo_1 = db.Column(db.String(255), nullable=False)  # ✅ Matches column name
    side_photo_2 = db.Column(db.String(255), nullable=False)  # ✅ Matches column name
    contact = db.Column(db.String(100), nullable=False)  # ✅ Matches database column
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())  # ✅ Matches `CURRENT_TIMESTAMP`

