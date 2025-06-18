from database import get_db_connection
from encryption import load_public_key, generate_aes_key, encrypt_with_aes, encrypt_with_rsa, decrypt_with_rsa, decrypt_with_aes, hash_password, verify_password

def set_conversation_key(user1_id, user2_id, key):
    """Set a conversation key between two users"""
    try:
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
            
        key_hash = hash_password(key)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            SELECT id FROM conversation_keys
            WHERE user1_id = %s AND user2_id = %s
        """
        cursor.execute(query, (user1_id, user2_id))
        existing_key = cursor.fetchone()
        
        if existing_key:
            query = """
                UPDATE conversation_keys
                SET key_hash = %s
                WHERE user1_id = %s AND user2_id = %s
            """
            cursor.execute(query, (key_hash, user1_id, user2_id))
        else:
            query = """
                INSERT INTO conversation_keys (user1_id, user2_id, key_hash)
                VALUES (%s, %s, %s)
            """
            cursor.execute(query, (user1_id, user2_id, key_hash))
            
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message': "Conversation key set successfully"
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

def verify_conversation_key(user1_id, user2_id, key):
    """Verify a conversation key between two users"""
    try:
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
            
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT key_hash FROM conversation_keys
            WHERE user1_id = %s AND user2_id = %s
        """
        cursor.execute(query, (user1_id, user2_id))
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not result:
            return {
                'success': False,
                'message': "No conversation key found"
            }
        
        if verify_password(result['key_hash'], key):
            return {
                'success': True,
                'message': "Conversation key verified successfully"
            }
        else:
            return {
                'success': False,
                'message': "Invalid conversation key"
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

def get_users(current_user_id):
    """Get all users except the current user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT id, username FROM users WHERE id != %s"
        cursor.execute(query, (current_user_id,))
        users = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'users': users,
            'message': f"Retrieved {len(users)} users"
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

def get_user_public_key(username):
    """Get a user's public key and ID"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT id, public_key FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return {
                'success': False,
                'message': "User not found"
            }
        
        return {
            'success': True,
            'user_id': user['id'],
            'public_key': user['public_key'],
            'message': "Public key retrieved successfully"
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

def send_message(sender_id, receiver_username, message, private_key):
    """Send an encrypted message to a user"""
    try:
        receiver_result = get_user_public_key(receiver_username)
        
        if not receiver_result['success']:
            return receiver_result
        
        receiver_id = receiver_result['user_id']
        receiver_public_key = load_public_key(receiver_result['public_key'])
        
        aes_key = generate_aes_key()
        
        encrypted_message = encrypt_with_aes(aes_key, message)
        
        encrypted_aes_key = encrypt_with_rsa(receiver_public_key, aes_key)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            INSERT INTO messages (sender_id, receiver_id, encrypted_message, encrypted_aes_key, iv)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            sender_id,
            receiver_id,
            encrypted_message['encrypted'],
            encrypted_aes_key,
            encrypted_message['iv']
        ))
        connection.commit()
        
        message_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message_id': message_id,
            'message': f"Message sent to {receiver_username} successfully"
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

def get_messages(user_id, private_key, other_user_id=None):
    """Get all messages for a user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT m.id, m.sender_id, m.receiver_id, m.encrypted_message, m.encrypted_aes_key, m.iv, m.timestamp,
                   u.username as sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.receiver_id = %s OR m.sender_id = %s)
        """
        params = [user_id, user_id]
        
        if other_user_id:
            query += " AND (m.sender_id = %s OR m.receiver_id = %s)"
            params.extend([other_user_id, other_user_id])
            
        query += " ORDER BY m.timestamp DESC"
        
        cursor.execute(query, params)
        encrypted_messages = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        decrypted_messages = []
        for msg in encrypted_messages:
            try:
                if msg['receiver_id'] == user_id:
                    encrypted_aes_key = base64.b64decode(msg['encrypted_aes_key'])
                    aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
                    
                    decrypted_message = decrypt_with_aes(
                        aes_key,
                        msg['encrypted_message'],
                        msg['iv']
                    ).decode('utf-8')
                    
                    decrypted_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'receiver_id': msg['receiver_id'],
                        'sender_username': msg['sender_username'],
                        'message': decrypted_message,
                        'timestamp': msg['timestamp']
                    })
                else:
                    decrypted_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'receiver_id': msg['receiver_id'],
                        'sender_username': msg['sender_username'],
                        'message': "[Message sent by you]",
                        'timestamp': msg['timestamp']
                    })
            except Exception as e:
                print(f"Error decrypting message {msg['id']}: {e}")
        
        return {
            'success': True,
            'messages': decrypted_messages,
            'message': f"Retrieved {len(decrypted_messages)} messages"
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