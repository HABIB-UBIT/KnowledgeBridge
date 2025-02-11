@app.route('/api/employee/login', methods=['POST'])
def login():
    data = request.json
    if not data.get('emp_email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            SELECT emp_id, emp_email, password, emp_role, b_id, emp_department
            FROM employee 
            WHERE emp_email = %s AND is_active = 1
        """, (data['emp_email'],))
        employee = cursor.fetchone()

        if not employee:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check password
        if bcrypt.checkpw(data['password'].encode(), employee[2].encode()):  # employee[2] is the password column
            access_token = create_access_token(identity={
                'emp_id': employee[0],  # emp_id is at index 0
                'emp_role': employee[3],  # emp_role is at index 3
                'b_id': employee[4],  # b_id is at index 4
                'emp_department': employee[5]  # emp_department is at index 5
            })
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'emp_role': employee[3]  # emp_role is at index 3
            }), 200
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()



# Login endpoint
# @app.route('/api/employee/login', methods=['POST'])
# def login():
#     data = request.json
#     if not data.get('emp_email') or not data.get('password'):
#         return jsonify({'error': 'Email and password required'}), 400

#     cursor = mysql.connection.cursor()
#     try:
#         cursor.execute("""
#             SELECT emp_id, emp_email, password, emp_role, b_id, emp_department
#             FROM employee 
#             WHERE emp_email = %s AND is_active = 1
#         """, (data['emp_email'],))
#         employee = cursor.fetchone()

#         if not employee:
#             return jsonify({'error': 'Invalid credentials'}), 401

#         if bcrypt.checkpw(data['password'].encode(), employee['password'].encode()):
#             access_token = create_access_token(identity={
#                 'emp_id': employee['emp_id'],
#                 'emp_role': employee['emp_role'],
#                 'b_id': employee['b_id'],
#                 'emp_department': employee['emp_department']
#             })
#             return jsonify({
#                 'message': 'Login successful',
#                 'access_token': access_token,
#                 'emp_role': employee['emp_role']
#             }), 200
#         return jsonify({'error': 'Invalid credentials'}), 401
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
#     finally:
#         cursor.close()