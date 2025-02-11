from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
import bcrypt
import os
from dotenv import load_dotenv
import re

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

def validate_registration_data(data):
    errors = []
    if not re.match(r'^\+?[1-9]\d{1,14}$', data.get('b_contact_num', '')):
        errors.append("Invalid contact number format")
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data.get('admin_email', '')):
        errors.append("Invalid admin email format")
    if len(data.get('admin_password', '')) < 8:
        errors.append("Password must be at least 8 characters")
    return errors

@app.route('/api/business/register', methods=['POST'])
def register_business():
    data = request.json
    required_fields = ['b_name', 'b_contact_num', 'admin_name', 'admin_email', 'admin_password']
    
    # Validation
    if missing := [f for f in required_fields if not data.get(f)]:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
    
    if errors := validate_registration_data(data):
        return jsonify({'errors': errors}), 400

    try:
        cursor = mysql.connection.cursor()
        
        # Check existing business
        cursor.execute("SELECT b_id FROM business WHERE b_name = %s OR b_contact_num = %s", 
                      (data['b_name'], data['b_contact_num']))
        if cursor.fetchone():
            return jsonify({'error': 'Business name or contact number already exists'}), 409

        # Start transaction
        cursor.execute("START TRANSACTION")

        # Insert business
        cursor.execute("""
            INSERT INTO business 
            (b_name, b_contact_num, b_ceo_name, b_website, b_num_emp)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            data['b_name'],
            data['b_contact_num'],
            data.get('b_ceo_name', data['admin_name']),
            data.get('b_website'),
            data.get('b_num_emp', 1)  # At least 1 employee (admin)
        ))
        business_id = cursor.lastrowid

        # Create super admin
        hashed_pw = bcrypt.hashpw(data['admin_password'].encode(), bcrypt.gensalt())
        cursor.execute("""
            INSERT INTO employee 
            (emp_name, emp_email, password, emp_role, b_id)
            VALUES (%s, %s, %s, 'super_admin', %s)
        """, (
            data['admin_name'],
            data['admin_email'],
            hashed_pw,
            business_id
        ))

        # Initialize storage
        ##########################################

        # Commit transaction
        mysql.connection.commit()

        return jsonify({
            'message': 'Business registered successfully',
            'business_id': business_id
        }), 201

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True)
