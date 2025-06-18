from database import get_db_connection
from encryption import is_valid_gmail, hash_password, verify_password, generate_rsa_key_pair, encrypt_private_key, decrypt_private_key

def register_user(username, password, security_question, security_answer):
    """Register a new user with Gmail ID and security question"""
    if not is_valid_gmail(username):
        return {
            'success': False,
            'message': "Username must be a valid Gmail address"
        }
    
    try:
        password_hash = hash_password(password)
        security_answer_hash = hash_password(security_answer)
        private_key, public_key = generate_rsa_key_pair()
        encrypted_private_key = encrypt_private_key(private_key, password)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            INSERT INTO users (username, password_hash, public_key, private_key_encrypted, security_question, security_answer_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (username, password_hash, public_key, encrypted_private_key, security_question, security_answer_hash))
        connection.commit()
        
        user_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'user_id': user_id,
            'message': f"User {username} registered successfully"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def login_user(username, password):
    """Login a user with Gmail ID"""
    if not is_valid_gmail(username):
        return {
            'success': False,
            'message': "Username must be a valid Gmail address"
        }
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return {
                'success': False,
                'message': "User not found"
            }
        
        if not verify_password(user['password_hash'], password):
            return {
                'success': False,
                'message': "Incorrect password"
            }
        
        private_key = decrypt_private_key(
            user['private_key_encrypted'],
            password
        )
        
        if not private_key:
            return {
                'success': False,
                'message': "Failed to decrypt private key"
            }
        
        return {
            'success': True,
            'user_id': user['id'],
            'username': user['username'],
            'public_key': user['public_key'],
            'private_key': private_key,
            'message': "Login successful"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def verify_security_answer(username, provided_answer):
    """Verify the security answer for a user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT security_answer_hash, security_question FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return {
                'success': False,
                'message': "User not found",
                'security_question': None
            }
        
        if verify_password(user['security_answer_hash'], provided_answer):
            return {
                'success': True,
                'message': "Security answer verified",
                'security_question': user['security_question']
            }
        else:
            return {
                'success': False,
                'message': "Incorrect security answer",
                'security_question': user['security_question']
            }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}",
            'security_question': None
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}",
            'security_question': None
        }

def reset_password(username, new_password, security_answer):
    """Reset a user's password after verifying security answer"""
    if not is_valid_gmail(username):
        return {
            'success': False,
            'message': "Username must be a valid Gmail address"
        }
    
    verify_result = verify_security_answer(username, security_answer)
    if not verify_result['success']:
        return verify_result
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT id FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            connection.close()
            return {
                'success': False,
                'message': "User not found"
            }
        
        new_private_key_pem, new_public_key = generate_rsa_key_pair()
        
        new_encrypted_private_key = encrypt_private_key(new_private_key_pem, new_password)
        
        new_password_hash = hash_password(new_password)
        
        query = """
            UPDATE users 
            SET password_hash = %s, public_key = %s, private_key_encrypted = %s 
            WHERE username = %s
        """
        cursor.execute(query, (new_password_hash, new_public_key, new_encrypted_private_key, username))
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message': "Password reset successfully. Note: A new key pair has been generated, so old messages cannot be decrypted."
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }