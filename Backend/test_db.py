from database import get_connection

try:
    connection = get_connection()

    cursor = connection.cursor()
    cursor.execute("SELECT DATABASE(), VERSION()")

    result = cursor.fetchone()

    print("Database connection successful!")
    print("Database:", result[0])
    print("Version:", result[1])

    cursor.close()
    connection.close()

except Exception as error:
    print("Database connection failed!")
    print("Error:", error)