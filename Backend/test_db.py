from database import get_connection

try:
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            NOW(),
            UTC_TIMESTAMP(),
            @@session.time_zone,
            @@global.time_zone
    """)

    result = cursor.fetchone()

    print("Database timezone test")
    print("----------------------")
    print("NOW():", result[0])
    print("UTC Time:", result[1])
    print("Session Timezone:", result[2])
    print("Global Timezone:", result[3])

    cursor.close()
    connection.close()

except Exception as error:
    print("Database test failed!")
    print("Error:", error)