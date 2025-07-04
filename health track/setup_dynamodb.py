import boto3

# Connect to DynamoDB (adjust region as needed)
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

# Create 'users' table
try:
    print("Creating 'users' table...")
    users_table = dynamodb.create_table(
        TableName='users',
        KeySchema=[
            {'AttributeName': 'email', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'email', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    users_table.wait_until_exists()
    print("'users' table created.")
except Exception as e:
    print("Users table creation skipped or failed:", e)

# Create 'appointments' table
try:
    print("Creating 'appointments' table...")
    appointments_table = dynamodb.create_table(
        TableName='appointments',
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    appointments_table.wait_until_exists()
    print("'appointments' table created.")
except Exception as e:
    print("Appointments table creation skipped or failed:", e)
