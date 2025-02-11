from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
import bcrypt
import os
from dotenv import load_dotenv
import re
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity
)

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

mysql = MySQL(app)
jwt = JWTManager(app)

def validate_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)

def tuple_to_dict(cursor_description, data_tuple):
    if not data_tuple:
        return None
    return {col[0]: value for col, value in zip(cursor_description, data_tuple)}

def validate_registration_data(data):
    errors = []
    if not re.match(r'^\+?[1-9]\d{1,14}$', data.get('b_contact_num', '')):
        errors.append("Invalid contact number format")
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data.get('admin_email', '')):
        errors.append("Invalid admin email format")
    if len(data.get('admin_password', '')) < 8:
        errors.append("Password must be at least 8 characters")
    return errors

@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user['emp_id'])  # Convert to string

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    emp_id = int(jwt_data["sub"])  # Convert back to integer
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            SELECT emp_id, emp_role, b_id, emp_department 
            FROM employee 
            WHERE emp_id = %s AND is_active = 1
        """, (emp_id,))
        user = tuple_to_dict(cursor.description, cursor.fetchone())
        return user
    finally:
        cursor.close()

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
            'business_id': business_id, 
            'success': True
        }), 201

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

# Auth Endpoints
@app.route('/api/employee/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'emp_email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400

        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT emp_id, password, emp_role, b_id, emp_department
            FROM employee 
            WHERE emp_email = %s AND is_active = 1
        """, (data['emp_email'],))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Invalid credentials'}), 401
            
        emp_id, password, emp_role, b_id, emp_department = result
        if not bcrypt.checkpw(data['password'].encode(), password.encode()):
            return jsonify({'error': 'Invalid credentials'}), 401

        access_token = create_access_token(identity={
            'emp_id': emp_id,
            'emp_role': emp_role,
            'b_id': b_id,
            'emp_department': emp_department
        })
        
        return jsonify({
            'message': 'Login successful',
            'emp_email': data['emp_email'],
            'business': b_id,
            'access_token': access_token,
            'emp_role': emp_role
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/api/employee/change-password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        data = request.get_json()
        if not data or 'old_password' not in data or 'new_password' not in data:
            return jsonify({'error': 'Both passwords required'}), 400

        if len(data['new_password']) < 8:
            return jsonify({'error': 'Password too short'}), 400

        emp_id = int(get_jwt_identity())
        cursor = mysql.connection.cursor()
        
        cursor.execute("SELECT password FROM employee WHERE emp_id = %s", (emp_id,))
        result = cursor.fetchone()
        
        if not result or not bcrypt.checkpw(data['old_password'].encode(), result[0].encode()):
            return jsonify({'error': 'Invalid old password'}), 401

        new_hash = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt())
        cursor.execute("UPDATE employee SET password = %s WHERE emp_id = %s", (new_hash, emp_id))
        mysql.connection.commit()
        
        return jsonify({'message': 'Password updated'}), 200

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

# Employee Management Endpoints
@app.route('/api/employees', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        current_user = get_jwt_identity()
        cursor = mysql.connection.cursor()
        
        # Get current user details
        cursor.execute("SELECT emp_role, b_id, emp_department FROM employee WHERE emp_id = %s", (current_user,))
        user_data = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not user_data or user_data['emp_role'] not in ['super_admin', 'team_lead']:
            return jsonify({'error': 'Permission denied'}), 403

        data = request.get_json()
        required = ['emp_name', 'emp_email', 'emp_role', 'password']
        if any(field not in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate roles
        if user_data['emp_role'] == 'team_lead' and data['emp_role'] in ['super_admin', 'team_lead']:
            return jsonify({'error': 'Cannot create elevated roles'}), 403
            
        if user_data['emp_role'] == 'super_admin' and data['emp_role'] == 'super_admin':
            return jsonify({'error': 'Only one super admin allowed'}), 400

        if not validate_email(data['emp_email']):
            return jsonify({'error': 'Invalid email'}), 400

        cursor.execute("SELECT emp_id FROM employee WHERE emp_email = %s", (data['emp_email'],))
        if cursor.fetchone():
            return jsonify({'error': 'Email exists'}), 409

        hashed_pw = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
        cursor.execute("""
            INSERT INTO employee 
            (emp_name, emp_email, password, emp_role, b_id, emp_department, emp_designation)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            data['emp_name'],
            data['emp_email'],
            hashed_pw,
            data['emp_role'],
            user_data['b_id'],
            data.get('emp_department', user_data.get('emp_department')),
            data.get('emp_designation', 'Employee')
        ))
        
        mysql.connection.commit()
        return jsonify({'message': 'Employee created'}), 201

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/api/employees/<int:emp_id>', methods=['PUT'])
@jwt_required()
def update_employee(emp_id):
    try:
        current_user_id = int(get_jwt_identity())
        cursor = mysql.connection.cursor()
        
        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id, emp_department 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        # Get target employee
        cursor.execute("""
            SELECT emp_id, emp_role, emp_department 
            FROM employee 
            WHERE emp_id = %s AND b_id = %s
        """, (emp_id, current_user['b_id']))
        target = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not target:
            return jsonify({'error': 'Employee not found'}), 404

        # Authorization check
        if current_user['emp_role'] == 'team_lead':
            if target['emp_role'] in ['super_admin', 'team_lead'] or \
               target['emp_department'] != current_user['emp_department']:
                return jsonify({'error': 'Unauthorized to modify this employee'}), 403

        data = request.get_json()
        updates = []
        params = []
        allowed_fields = ['emp_name', 'emp_email', 'emp_department', 'emp_designation', 'is_active']

        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = %s")
                params.append(data[field])

        # Handle role updates
        if current_user['emp_role'] == 'super_admin' and 'emp_role' in data:
            if data['emp_role'] == 'super_admin' and target['emp_role'] != 'super_admin':
                return jsonify({'error': 'Cannot assign super admin role'}), 400
            updates.append("emp_role = %s")
            params.append(data['emp_role'])

        if not updates:
            return jsonify({'error': 'No valid fields to update'}), 400

        params.append(emp_id)
        query = f"UPDATE employee SET {', '.join(updates)} WHERE emp_id = %s"
        cursor.execute(query, tuple(params))
        mysql.connection.commit()
        
        return jsonify({'message': 'Employee updated successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/api/employees/<int:emp_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(emp_id):
    try:
        current_user_id = int(get_jwt_identity())
        cursor = mysql.connection.cursor()
        
        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id, emp_department 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not current_user or current_user['emp_role'] not in ['super_admin', 'team_lead']:
            return jsonify({'error': 'Insufficient permissions'}), 403

        # Get target employee
        cursor.execute("""
            SELECT emp_role, emp_department 
            FROM employee 
            WHERE emp_id = %s AND b_id = %s
        """, (emp_id, current_user['b_id']))
        target = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not target:
            return jsonify({'error': 'Employee not found'}), 404

        # Authorization checks
        if target['emp_role'] == 'super_admin':
            return jsonify({'error': 'Cannot delete super admin'}), 403

        if current_user['emp_role'] == 'team_lead':
            if target['emp_role'] == 'team_lead' or \
               target['emp_department'] != current_user['emp_department']:
                return jsonify({'error': 'Unauthorized to delete this employee'}), 403

        cursor.execute("DELETE FROM employee WHERE emp_id = %s", (emp_id,))
        mysql.connection.commit()
        return jsonify({'message': 'Employee deleted successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True)

