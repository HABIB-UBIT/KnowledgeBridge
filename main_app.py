from flask import Flask, jsonify, request
# from flask_mysqldb import MySQL
import mysql.connector
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
from flask_cors import CORS, cross_origin
from langchain.vectorstores import Chroma
import chromadb
from langchain.embeddings import OpenAIEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import ChatOpenAI
from langchain.document_loaders import PyPDFLoader
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain.prompts import PromptTemplate
from flask_socketio import SocketIO, emit, send
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
load_dotenv()

os.environ['OPENAI_API_KEY'] = os.getenv('OPEN_AI')

app = Flask(__name__)
CORS(app)
# Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
socketio = SocketIO(app, cors_allowed_origins="*")
dbconfig = {
    "host": os.getenv('MYSQL_HOST'),
    "user": os.getenv('MYSQL_USER'),
    "password": os.getenv('MYSQL_PASSWORD'),
    "database": os.getenv('MYSQL_DB')
}
jwt = JWTManager(app)


def get_db_connection():
    return mysql.connector.connect(**dbconfig)
    
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

def add_documents_to_collection(collection, docs):
    embedding_function = OpenAIEmbeddings()

    # Extract page content and metadata in bulk
    page_contents = [doc.page_content for doc in docs]
    metadata_list = [doc.metadata for doc in docs]
    doc_ids = [f"doc_{i}" for i in range(len(docs))]

    # Parallel embedding computation
    with ThreadPoolExecutor(max_workers=5) as executor:
        embeddings = list(executor.map(embedding_function.embed_documents, [page_contents]))

    # Add all documents at once (bulk insert)
    collection.add(
        ids=doc_ids,
        embeddings=embeddings[0],  # Extract embeddings list
        metadatas=metadata_list,
        documents=page_contents
    )        
def make_new_collection(collection_name, docs = None):
    client = chromadb.PersistentClient(path="./chroma_db")
    collection = client.get_or_create_collection(collection_name)
    if docs:
        add_documents_to_collection(collection, docs)
    return collection

def load_collection(collection_name):
    embeddings = OpenAIEmbeddings()
    return Chroma(
        persist_directory="./chroma_db",  # Path where ChromaDB stores data
        embedding_function=embeddings,
        collection_name=collection_name  # Load only this collection
    )

def calculate_remaining_percentage(used, used_unit, total, total_unit):
    # Conversion factors
    unit_to_kb = {"KB": 1, "MB": 1024, "GB": 1024 * 1024}
    
    # Convert both used and total to KB
    used_kb = used * unit_to_kb[used_unit.upper()]
    total_kb = total * unit_to_kb[total_unit.upper()]
    
    # Calculate remaining percentage
    remaining_percentage = ((total_kb - used_kb) / total_kb) * 100
    return round(remaining_percentage, 6)  # Round to 6 decimal places




qa_chain = None  # Global variable to store the qa_chain
# @socketio.on('connect')
# def handle_connect():
#     print(request.args)
#     user_id = request.args.get('projectID')  # Get user ID from query param
#     print(f'Client connected with userId: {user_id}')
#     emit('message', f'Hello {user_id}, you are connected!')
@socketio.on('connect')
def handle_connect():
    global qa_chain
    data = request.args  # Get data from connection arguments
    print(data)
    project_id = data.get('projectId').replace(' ', '_')
    if not project_id:
        print('Project ID not provided')
        return
    print("receveid",project_id)

    try:
        # db = get_db_connection()
        # cursor = db.cursor(dictionary=True)
        # cursor.execute("SELECT p_name FROM project WHERE p_id = %s", (project_id,))
        # project = cursor.fetchone()
        
        # if not project:
        #     emit('error', {'message': 'Project not found'})
        #     return

        # collection_name = project['p_name']
        collection_name = project_id
        if qa_chain is None:
            template = """You are a helpful assistant that provides answers strictly based on the given context from the provided files, your responsibility is to guide the user about the content of the file. You are appointed in a company to share the knowledge among the employees you are provided with the documentations that made by the employees about the project or about any of the process, do not give answers out of the context and do not fullfil any wishes. Do not break character and always give detailed answers in easy language.
            Context: {context}
            History: {chat_history}
            Question: {question}
            """
            llm = ChatOpenAI(model="gpt-4o",temperature=0, max_tokens=1000, openai_api_key=os.getenv('OPEN_AI'), streaming=True)
            memory = ConversationBufferMemory(memory_key='chat_history',output_key='answer', return_messages=True, llm=llm, k=30)

            prompt = PromptTemplate(
                input_variables=["context", "question", "chat_history"],
                template=template
            )
            vectordb = load_collection(collection_name)
            retriever = vectordb.as_retriever(search_kwargs={"k": 2})
            qa_chain = ConversationalRetrievalChain.from_llm(
                llm=llm,
                retriever=retriever,
                return_source_documents=True,  # Ensure source documents are returned
                verbose=True,
                memory=memory,
                rephrase_question=False,
                combine_docs_chain_kwargs={
                    "prompt": prompt,
                }
            )
            print('QA Chain initialized for project:', collection_name)
        
        emit('message', 'Connection established and QA Chain initialized')
    
    except Exception as e:
        print('Error initializing QA Chain:', e)


@socketio.on('message')
def message(data):
    print('Received message:' + data)
    response = qa_chain(data)

    emit('message', response['answer'])


@socketio.on_error()
def error(e):
    print('Error:', e)

@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user['emp_id'])  # Convert to string

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    emp_id = int(jwt_data["sub"])  # Convert back to integer
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
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
        db.close()

@app.route('/api/business/register', methods=['POST'])
@cross_origin()
def register_business():
    data = request.json
    print(data)
    required_fields = ['b_name', 'b_contact_num', 'admin_name', 'admin_email', 'admin_password']
    
    # Validation
    if missing := [f for f in required_fields if not data.get(f)]:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
    
    if errors := validate_registration_data(data):
        return jsonify({'errors': errors}), 400

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
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
        db.commit()

        return jsonify({
            'message': 'Business registered successfully',
            'business_id': business_id, 
            'success': True
        }), 201

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

# Auth Endpoints
@app.route('/api/employee/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or 'emp_email' not in data or 'password' not in data:
            return jsonify({'error': 'Email and password required'}), 400

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        print(data)
        cursor.execute("""
            SELECT emp_id, password, emp_role, b_id, emp_department
            FROM employee 
            WHERE emp_email = %s AND is_active = 1
        """, (data['emp_email'],))
        
        result = cursor.fetchone()
        print(result)
        if not result:
            return jsonify({'message': 'Invalid credentials'}), 401
            
        password = result['password']
        if not bcrypt.checkpw(data['password'].encode(), password.encode()):
            return jsonify({'message': 'Invalid credentials'}), 401

        access_token = create_access_token(identity={
            'emp_id': result['emp_id'],
            'emp_role': result['emp_role'],
            'b_id': result['b_id'],
            'emp_department': result['emp_department']
        })
        
        return jsonify({
            'message': 'Login successful',
            'emp_email': data['emp_email'],
            'business': result['b_id'],
            'access_token': access_token,
            'emp_role': result['emp_role'],
            'success': True
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/employee/logout', methods=['POST'])
def logout():
    return jsonify({'message': 'Logout successful'}), 200

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
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT password FROM employee WHERE emp_id = %s", (emp_id,))
        result = cursor.fetchone()
        
        if not result or not bcrypt.checkpw(data['old_password'].encode(), result[0].encode()):
            return jsonify({'error': 'Invalid old password'}), 401

        new_hash = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt())
        cursor.execute("UPDATE employee SET password = %s WHERE emp_id = %s", (new_hash, emp_id))
        db.commit()
        
        return jsonify({'message': 'Password updated'}), 200

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

# Employee Management Endpoints
@app.route('/api/employees', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        current_user = get_jwt_identity()
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get current user details
        cursor.execute("SELECT emp_role, b_id FROM employee WHERE emp_id = %s", (current_user,))
        user_data = cursor.fetchone()
        print(user_data)
        if not user_data or user_data['emp_role'] not in ['super_admin', 'admin']:
            return jsonify({'error': 'Permission denied'}), 403

        data = request.get_json()
        required = ['memberName', 'memberEmail', 'memberRole', 'password']
        if any(field not in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate roles
        if user_data['emp_role'] == 'admin' and data['memberRole'] in ['super_admin', 'admin']:
            return jsonify({'error': 'Cannot create elevated roles'}), 403
            
        if user_data['emp_role'] == 'super_admin' and data['memberRole'] == 'super_admin':
            return jsonify({'error': 'Only one super admin allowed'}), 400

        if not validate_email(data['memberEmail']):
            return jsonify({'error': 'Invalid email'}), 400

        cursor.execute("SELECT emp_id FROM employee WHERE emp_email = %s", (data['memberEmail'],))
        if cursor.fetchone():
            return jsonify({'error': 'Email exists'}), 409

        hashed_pw = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
        print(data['memberName'],
            data['memberEmail'],
            hashed_pw,
            data['memberRole'],
            user_data['b_id'],
            data.get('emp_department', 'General'),
            data.get('memberDesignation', 'Employee'),
            data.get('emp_manager', 'Null'),
            int(current_user))
        cursor.execute("""
            INSERT INTO employee 
            (emp_name, emp_email, password, emp_role, b_id, emp_department, emp_designation, emp_manager, is_active, added_by)
            VALUES (%s, %s,
             %s, %s, %s, %s, %s, %s, 1, %s)
        """, (
            data['memberName'],
            data['memberEmail'],
            hashed_pw,
            data['memberRole'],
            user_data['b_id'],
            None,
            data.get('memberDesignation', 'Employee'),
            None,
            int(current_user)
        ))
        
        emp_id = cursor.lastrowid
        print(data['projectName'])
        if data['projectName']:
            cursor.execute("INSERT INTO project_members (p_id, emp_id) VALUES (%s, %s)", (data['projectName'], emp_id))
            print("project_members added")


        db.commit()
        return jsonify({'message': 'Employee created', 'success': True, 'employee_id': emp_id}), 201

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/employees/<int:emp_id>', methods=['PUT'])
@jwt_required()
def update_employee(emp_id):
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
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
        if current_user['emp_role'] == 'admin':
            if target['emp_role'] in ['super_admin', 'admin'] or \
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
        db.commit()
        
        return jsonify({'message': 'Employee updated successfully'}), 200

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/employees/<int:emp_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(emp_id):
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id, emp_department 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not current_user or current_user['emp_role'] not in ['super_admin', 'admin']:
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

        if current_user['emp_role'] == 'admin':
            if target['emp_role'] == 'admin' or \
               target['emp_department'] != current_user['emp_department']:
                return jsonify({'error': 'Unauthorized to delete this employee'}), 403

        cursor.execute("DELETE FROM employee WHERE emp_id = %s", (emp_id,))
        db.commit()
        return jsonify({'message': 'Employee deleted successfully'}), 200

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/employees', methods=['GET'])
@jwt_required()
def get_employees():
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id, emp_department 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = tuple_to_dict(cursor.description, cursor.fetchone())
        
        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        if current_user['emp_role'] == 'admin':
            cursor.execute("""
                SELECT emp_id, emp_name, emp_email, emp_role, emp_department, emp_designation, is_active
                FROM employee 
                WHERE b_id = %s AND emp_department = %s
            """, (current_user['b_id'], current_user['emp_department']))
        else:
            cursor.execute("""
                SELECT emp_id, emp_name, emp_email, emp_role, emp_department, emp_designation, is_active
                FROM employee 
                WHERE b_id = %s
            """, (current_user['b_id'],))
        
        employees = [tuple_to_dict(cursor.description, row) for row in cursor.fetchall()]
        return jsonify({'employees': employees}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()
    
# Document Management Endpoints
@app.route('/api/documents', methods=['POST'])
@jwt_required()
def upload_document():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        if not data or 'document' not in data:
            return jsonify({'error': 'Document required'}), 400

        if not data['document'].get('filename'):
            return jsonify({'error': 'Filename required'}), 400

        if not data['document'].get('content'):
            return jsonify({'error': 'Content required'}), 400

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT b_id FROM employee WHERE emp_id = %s", (current_user,))
        business_id = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO document 
            (doc_name, doc_content, b_id, uploaded_by)
            VALUES (%s, %s, %s, %s)
        """, (
            data['document']['filename'],
            data['document']['content'],
            business_id,
            current_user
        ))
        document_id = cursor.lastrowid
        db.commit()
        
        return jsonify({'message': 'Document uploaded', 'document_id': document_id}), 201

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/get_dashboard_data', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    try:
        current_user = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        print(current_user)
        cursor.execute("SELECT emp_role, b_id FROM employee WHERE emp_id = %s", (current_user,))
        user_info = cursor.fetchone()
        business_id = user_info['b_id']
        emp_role = user_info['emp_role']
        
        if emp_role == 'super_admin':
            cursor.execute("SELECT COUNT(*) as employee_count FROM employee WHERE b_id = %s AND emp_role != 'super_admin'", (business_id,))
            employee_count = cursor.fetchone()['employee_count']
            
            cursor.execute("SELECT COUNT(*) as project_count FROM project WHERE b_id = %s", (business_id,))
            project_count = cursor.fetchone()['project_count']

            cursor.execute("""
                SELECT e.*, b.b_name, added_by_emp.emp_name as added_by_name
                FROM employee e
                JOIN business b ON e.b_id = b.b_id
                LEFT JOIN employee added_by_emp ON e.added_by = added_by_emp.emp_id
                WHERE e.b_id = %s AND e.created_at >= NOW() - INTERVAL 1 WEEK AND e.emp_role != 'super_admin'
            """, (business_id,))
            new_employees = cursor.fetchall()

            for employee in new_employees:
                cursor.execute("""
                SELECT p.p_id, p.p_name
                FROM project p
                JOIN project_members pm ON p.p_id = pm.p_id
                WHERE pm.emp_id = %s
                """, (employee['emp_id'],))
                employee['projects'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT p.*, e.emp_name as project_leader_name
                FROM project p
                LEFT JOIN employee e ON p.p_leader = e.emp_id
                WHERE p.b_id = %s AND p.created_at >= NOW() - INTERVAL 1 WEEK
            """, (business_id,))
            new_projects = cursor.fetchall()

            cursor.execute("""
                SELECT d.*, e.emp_name as uploaded_by_name, p.p_name as project_name
                FROM document d
                JOIN employee e ON d.uploaded_by = e.emp_id
                LEFT JOIN project p ON d.p_id = p.p_id
                WHERE d.b_id = %s AND d.created_at >= NOW() - INTERVAL 1 WEEK
            """, (business_id,))
            new_documents = cursor.fetchall()
        else:
            cursor.execute("SELECT COUNT(*) as employee_count FROM project_members WHERE emp_id = %s", (current_user,))
            employee_count = cursor.fetchone()['employee_count']
            
            cursor.execute("SELECT COUNT(*) as project_count FROM project_members WHERE emp_id = %s", (current_user,))
            project_count = cursor.fetchone()['project_count']

            cursor.execute("""
                    SELECT DISTINCT e.*, 
                        b.b_name, 
                        added_by_emp.emp_name AS added_by_name, 
                        pm.p_id
                    FROM employee e
                    JOIN business b ON e.b_id = b.b_id
                    LEFT JOIN employee added_by_emp ON e.added_by = added_by_emp.emp_id
                    JOIN project_members pm ON e.emp_id = pm.emp_id
                    WHERE 
                        pm.p_id IN (SELECT p_id FROM project_members WHERE emp_id = %s)
                        OR e.added_by = %s 
                        AND e.created_at >= NOW() - INTERVAL 1 WEEK
                        AND e.emp_role != 'super_admin'
                    ORDER BY e.created_at DESC;
                """, (current_user, current_user))

            new_employees = cursor.fetchall()

            for employee in new_employees:
                cursor.execute("""
                SELECT p.p_id, p.p_name
                FROM project p
                JOIN project_members pm ON p.p_id = pm.p_id
                WHERE pm.emp_id = %s
                """, (employee['emp_id'],))
                employee['projects'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT p.*, e.emp_name as project_leader_name
                FROM project p
                LEFT JOIN employee e ON p.p_leader = e.emp_id
                JOIN project_members pm ON p.p_id = pm.p_id
                WHERE pm.emp_id = %s AND p.created_at >= NOW() - INTERVAL 1 WEEK
            """, (current_user,))
            new_projects = cursor.fetchall()

            cursor.execute("""
                SELECT d.*, e.emp_name as uploaded_by_name, p.p_name as project_name
                FROM document d
                JOIN employee e ON d.uploaded_by = e.emp_id
                LEFT JOIN project p ON d.p_id = p.p_id
                JOIN project_members pm ON d.p_id = pm.p_id
                WHERE pm.emp_id = %s AND d.created_at >= NOW() - INTERVAL 1 WEEK
            """, (current_user,))
            new_documents = cursor.fetchall()

        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for document in new_documents:
            size = document['d_size']
            unit_index = 0
            while size >= 1024 and unit_index < len(units) - 1:
                size /= 1024
                unit_index += 1
            document['d_size_readable'] = f"{size:.2f} {units[unit_index]}"
        
        cursor.execute("SELECT SUM(d_size) as total_storage_used FROM document WHERE b_id = %s", (business_id,))
        total_storage_used = cursor.fetchone()['total_storage_used']
        size = total_storage_used if total_storage_used else 0
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        total_storage_used = f"{size:.2f} {units[unit_index]}"

        cursor.execute("""
            SELECT e.*, b.b_name 
            FROM employee e 
            JOIN business b ON e.b_id = b.b_id 
            WHERE e.emp_id = %s
        """, (current_user,))
        user = cursor.fetchone()
        storage_details = total_storage_used.split(' ')
        business_data = {
            'new_employees': new_employees,
            'new_projects': new_projects,
            'new_documents': new_documents,
            'total_storage_used': total_storage_used,
            'storageRemains': calculate_remaining_percentage(float(storage_details[0]), str(storage_details[1]), 10, 'GB'),
            'user': user
        }
        
        return jsonify({'employee_count': employee_count, "project_count": project_count, 'business_data': business_data, "total_storage_used": total_storage_used}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/project/add', methods=['POST'])
@jwt_required()
def add_project():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        if not data or 'projectName' not in data:
            return jsonify({'error': 'Project name required'}), 400

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT b_id FROM employee WHERE emp_id = %s", (current_user,))
        business_id = cursor.fetchone()['b_id']
        print(data)
        cursor.execute("""
            INSERT INTO project 
            (p_name, p_description, created_by, b_id, is_active, p_duration, p_leader, start_date, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['projectName'],
            data.get('projectDescription', ''),
            current_user,
            business_id,
            True,
            data.get('projectDuration', ''),
            data.get('projectLeader'),
            data.get('projectStartDate', '').split('T')[0] if data.get('projectStartDate') else None,
            data.get('projectStatus', 'On going')
        ))
        print(data)
        project_id = cursor.lastrowid
        make_new_collection(data['projectName'].replace(' ', '_'))
        if data.get('projectLeader'):
            cursor.execute("INSERT INTO project_members (p_id, emp_id) VALUES (%s, %s)", (project_id, data.get('projectLeader')))

        db.commit()
        
        return jsonify({'message': 'Project added', 'project_id': project_id, 'success': True}), 201

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/p_leader_options', methods=['GET'])
@jwt_required()
def get_p_leader_options():
    try:
        current_user = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT emp_role, b_id FROM employee WHERE emp_id = %s", (current_user,))
        user_info = cursor.fetchone()
        business_id = user_info['b_id']
        emp_role = user_info['emp_role']

        if emp_role == 'super_admin':
            cursor.execute("""
                SELECT emp_id, emp_name, emp_email
                FROM employee 
                WHERE b_id = %s AND emp_role = 'admin'
            """, (business_id,))
            team_leads = cursor.fetchall()
        else:
            cursor.execute("""
                SELECT emp_id, emp_name, emp_email
                FROM employee 
                WHERE emp_id = %s
            """, (current_user,))
            team_leads = cursor.fetchall()

        return jsonify({'team_leads': team_leads}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/get_all_projects', methods=['GET'])
@jwt_required()
def get_all_projects():
    try:
        current_user = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get current user details
        cursor.execute("SELECT emp_role, b_id FROM employee WHERE emp_id = %s", (current_user,))
        user_info = cursor.fetchone()
        business_id = user_info['b_id']
        emp_role = user_info['emp_role']
        
        if emp_role == 'super_admin':
            cursor.execute("SELECT * FROM project WHERE b_id = %s", (business_id,))
        else:
            cursor.execute("""
                SELECT p.* 
                FROM project p
                JOIN project_members pm ON p.p_id = pm.p_id
                WHERE pm.emp_id = %s AND p.b_id = %s
            """, (current_user, business_id))
        
        projects = cursor.fetchall()

        cursor.execute("""
            SELECT e.*, b.b_name 
            FROM employee e 
            JOIN business b ON e.b_id = b.b_id 
            WHERE e.emp_id = %s
        """, (current_user,))
        user = cursor.fetchone()
        return jsonify({'projects': projects, 'user': user}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/documents/upload', methods=['POST'])
@jwt_required()
def upload_pdf_document():
    try:
        current_user = int(get_jwt_identity())
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400

       
        files = request.files.getlist('file')  # Get multiple files
        project_id = request.form.get('projectId') 
        print(project_id)
        document_ids = []
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        # get projectName
        cursor.execute("SELECT p_name FROM project WHERE p_id = %s", (project_id,))
        project_name = cursor.fetchone()['p_name']
        cursor.execute("SELECT b_id FROM employee WHERE emp_id = %s", (current_user,))
        business_id = cursor.fetchone()['b_id']
        for file in files:
            if file.filename == '':
                continue  # Skip empty files

            if not file.filename.endswith('.pdf'):
                return jsonify({'error': 'Only PDF files are allowed'}), 400

            upload_dir = 'uploads'
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)
            file_path = os.path.join(upload_dir, file.filename)
            file.save(file_path)
            loader = PyPDFLoader(file_path)
            documents = loader.load()

            # Chunking the text
            # text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
            # chunks = text_splitter.split_documents(documents)

            # Convert chunks to a list of texts
            # docs = [chunk.page_content for chunk in chunks]
            make_new_collection(project_name.replace(' ', '_'), documents)
            cursor.execute("""
                INSERT INTO document 
                (d_name, d_size, uploaded_by, b_id, p_id, d_download_url, d_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                file.filename,
                os.path.getsize(file_path),
                current_user,
                business_id,
                project_id,
                file_path,
                'pdf'
            ))

            document_ids.append(cursor.lastrowid)
        db.commit()

        

        return jsonify({'message': 'PDF documents uploaded', 'document_ids': document_ids}), 201

    except Exception as e:
        db.rollback()
        print(e)
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/projects/<int:p_id>/employees', methods=['GET'])
@jwt_required()
def get_employees_and_docs_by_project(p_id):
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = cursor.fetchone()
        
        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        # Get employees by project ID
        cursor.execute("""
            SELECT e.emp_id, e.emp_name, e.emp_email, e.emp_role, e.emp_department, e.emp_designation, e.is_active
            FROM employee e
            JOIN project_members pm ON e.emp_id = pm.emp_id
            WHERE pm.p_id = %s AND e.b_id = %s
        """, (p_id, current_user['b_id']))
        employees = cursor.fetchall()
        

        # get documents by project id
        cursor.execute("""
            SELECT d.*, e.emp_name as uploaded_by_name
            FROM document d
            JOIN employee e ON d.uploaded_by = e.emp_id
            WHERE d.p_id = %s AND d.b_id = %s
        """, (p_id, current_user['b_id']))
        documents = cursor.fetchall()
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for document in documents:
            size = document['d_size']
            unit_index = 0
            while size >= 1024 and unit_index < len(units) - 1:
                size /= 1024
                unit_index += 1
            document['d_size_readable'] = f"{size:.2f} {units[unit_index]}"
        
        print(employees)
        return jsonify({'employees': employees, 'documents': documents}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/projects', methods=['GET'])
@jwt_required()
def get_projects_by_business():
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = cursor.fetchone()
        
        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        if current_user['emp_role'] == 'admin' or current_user['emp_role'] == 'member':
            cursor.execute("""
                SELECT * 
                FROM project p
                JOIN project_members pm ON p.p_id = pm.p_id
                WHERE pm.emp_id = %s AND p.b_id = %s
            """, (current_user_id, current_user['b_id']))
        else:
            cursor.execute("""
                SELECT * 
                FROM project 
                WHERE b_id = %s
            """, (current_user['b_id'],))
        
        projects = cursor.fetchall()
        cursor.execute("""
            SELECT e.*, b.b_name 
            FROM employee e 
            JOIN business b ON e.b_id = b.b_id 
            WHERE e.emp_id = %s
        """, (current_user_id,))
        user = cursor.fetchone()
        return jsonify({'projects': projects, 'success': True, 'user': user}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/member/documents', methods=['GET'])
@jwt_required()
def get_documents_by_member():
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = cursor.fetchone()
        
        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        if current_user['emp_role'] == 'super_admin':
            # Get all documents for the business
            cursor.execute("""
            SELECT d.*, e.emp_name as uploaded_by_name, p.p_name as project_name
            FROM document d
            JOIN employee e ON d.uploaded_by = e.emp_id
            LEFT JOIN project p ON d.p_id = p.p_id
            WHERE d.b_id = %s
            """, (current_user['b_id'],))
        else:
            # Get projects assigned to the member
            cursor.execute("""
            SELECT p_id 
            FROM project_members 
            WHERE emp_id = %s
            """, (current_user_id,))
            project_ids = [row['p_id'] for row in cursor.fetchall()]

            if not project_ids:
                return jsonify({'documents': []}), 200

            # Get documents related to the projects
            cursor.execute("""
            SELECT d.*, e.emp_name as uploaded_by_name, p.p_name as project_name
            FROM document d
            JOIN employee e ON d.uploaded_by = e.emp_id
            LEFT JOIN project p ON d.p_id = p.p_id
            WHERE d.p_id IN (%s) AND d.b_id = %s
            """ % (','.join(['%s'] * len(project_ids)), '%s'), (*project_ids, current_user['b_id']))

        documents = cursor.fetchall()
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for document in documents:
            size = document['d_size']
            unit_index = 0
            while size >= 1024 and unit_index < len(units) - 1:
                size /= 1024
                unit_index += 1
            document['d_size_readable'] = f"{size:.2f} {units[unit_index]}"
        
        cursor.execute("""
            SELECT e.*, b.b_name 
            FROM employee e 
            JOIN business b ON e.b_id = b.b_id 
            WHERE e.emp_id = %s
        """, (current_user_id,))
        user = cursor.fetchone()
        return jsonify({'documents': documents, 'success': True, 'user': user}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


@app.route('/api/employees_by_role', methods=['GET'])
@jwt_required()
def get_employees_by_role():
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Get current user details
        cursor.execute("""
            SELECT emp_role, b_id 
            FROM employee 
            WHERE emp_id = %s
        """, (current_user_id,))
        current_user = cursor.fetchone()

        if not current_user:
            return jsonify({'error': 'Unauthorized'}), 401

        if current_user['emp_role'] == 'super_admin':
            # Get all employees for the business except super_admin
            cursor.execute("""
                SELECT e.emp_id, e.emp_name, e.emp_email, e.emp_role, e.emp_department, e.emp_designation, e.is_active, a.emp_name as added_by_name, p.p_name as p_name, e.created_at as created_at
                FROM employee e
                LEFT JOIN employee a ON e.added_by = a.emp_id
                LEFT JOIN project_members pm ON e.emp_id = pm.emp_id
                LEFT JOIN project p ON pm.p_id = p.p_id
                WHERE e.b_id = %s AND e.emp_role != 'super_admin'
            """, (current_user['b_id'],))
        elif current_user['emp_role'] == 'admin':
            # Get projects assigned to the admin
            cursor.execute("""
                SELECT p_id 
                FROM project_members 
                WHERE emp_id = %s
            """, (current_user_id,))
            project_ids = [row['p_id'] for row in cursor.fetchall()]

            if not project_ids:
                return jsonify({'employees': []}), 200

            # Get employees related to the projects except super_admin
            cursor.execute("""
                SELECT DISTINCT e.emp_id, e.emp_name, e.emp_email, e.emp_role, e.emp_department, e.emp_designation, e.is_active, p.p_name as project_name, a.emp_name as added_by_name
                FROM employee e
                JOIN project_members pm ON e.emp_id = pm.emp_id
                JOIN project p ON pm.p_id = p.p_id
                LEFT JOIN employee a ON e.added_by = a.emp_id
                WHERE pm.p_id IN (%s) AND e.b_id = %s AND e.emp_role != 'super_admin'
            """ % (','.join(['%s'] * len(project_ids)), '%s'), (*project_ids, current_user['b_id']))
        else:
            return jsonify({'error': 'Insufficient permissions'}), 403

        employees = cursor.fetchall()
        cursor.execute("""
            SELECT e.*, b.b_name 
            FROM employee e 
            JOIN business b ON e.b_id = b.b_id 
            WHERE e.emp_id = %s
        """, (current_user_id,))
        user = cursor.fetchone()
        return jsonify({'employees': employees, 'success': True, 'user': user}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile_details():
    try:
        current_user_id = int(get_jwt_identity())
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Get current user details
        cursor.execute("""
            SELECT e.emp_id, e.emp_name, e.emp_email, e.emp_role, e.emp_department, e.emp_designation, e.is_active, b.b_name
            FROM employee e
            JOIN business b ON e.b_id = b.b_id
            WHERE e.emp_id = %s
        """, (current_user_id,))
        user_details = cursor.fetchone()

        if not user_details:
            return jsonify({'error': 'User not found'}), 404

        # Get projects assigned to the user
        cursor.execute("""
            SELECT p.p_id, p.p_name, p.p_description, p.p_duration, p.start_date, p.status, e.emp_name as project_leader_name
            FROM project p
            JOIN project_members pm ON p.p_id = pm.p_id
            LEFT JOIN employee e ON p.p_leader = e.emp_id
            WHERE pm.emp_id = %s
        """, (current_user_id,))
        projects = cursor.fetchall()

        return jsonify({'user_details': user_details, 'projects': projects, 'success': True}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        db.close()


if __name__ == '__main__':
    socketio.run(app, debug=True)

