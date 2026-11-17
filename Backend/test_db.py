from database import get_connection

try:
    connection = get_connection()

    if connection.is_connected():
        print("MySQL Connection Successful!")
        print("Database:", connection.database)

    connection.close()

except Exception as error:
    print("Connection Failed!")
    print(error)