import mysql.connector

def create_database():
    """Create the database and tables if they don't exist"""
    try:
        connection = mysql.connector.connect(
            host="192.168.1.2",
            user="kanchan",
            password="1234"
        )
        cursor = connection.cursor()
        
        cursor.execute("CREATE DATABASE IF NOT EXISTS secure_messaging")
        print("Database created successfully")
        
        cursor.execute("USE secure_messaging")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL,
                security_question VARCHAR(255) NOT NULL,
                security_answer_hash VARCHAR(255) NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                encrypted_message TEXT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversation_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user1_id INT NOT NULL,
                user2_id INT NOT NULL,
                key_hash VARCHAR(255) NOT NULL,
                FOREIGN KEY (user1_id) REFERENCES users(id),
                FOREIGN KEY (user2_id) REFERENCES users(id),
                UNIQUE KEY unique_conversation (user1_id, user2_id)
            )
        """)
        
        print("Tables created successfully")
        
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_db_connection():
    """Get a connection to the database"""
    return mysql.connector.connect(
        host="192.168.1.2",
        user="kanchan",
        password="1234",
        database="secure_messaging"
    )

def delete_user(user_id):
    """Delete a user and their associated data"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM messages WHERE sender_id = %s OR receiver_id = %s", (user_id, user_id))
        cursor.execute("DELETE FROM conversation_keys WHERE user1_id = %s OR user2_id = %s", (user_id, user_id))
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message': "User deleted successfully"
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

def delete_messages(user_id, other_user_id):
    """Delete messages between two users"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute("""
            DELETE FROM messages 
            WHERE (sender_id = %s AND receiver_id = %s) 
            OR (sender_id = %s AND receiver_id = %s)
        """, (user_id, other_user_id, other_user_id, user_id))
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message': "Messages deleted successfully"
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