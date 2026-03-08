from app import app, db, Report, ContactMessage 

with app.app_context():
    print("Dropping all tables (if they exist)...")
    db.drop_all()
    print("Creating all tables based on SQLAlchemy models...")
    db.create_all() 

print("Database and tables created successfully based on SQLAlchemy models!")
if hasattr(Report, '__tablename__'):
    print(f"Model 'Report' targets table: {Report.__tablename__}")
else:
    print("Model 'Report' does not have a __tablename__ attribute.")

if hasattr(ContactMessage, '__tablename__'):
    print(f"Model 'ContactMessage' targets table: {ContactMessage.__tablename__}")
else:
    print("Model 'ContactMessage' does not have a __tablename__ attribute.")

print(f"Database URI being used: {app.config['SQLALCHEMY_DATABASE_URI']}")