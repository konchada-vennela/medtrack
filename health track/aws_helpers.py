# aws_helpers.py

import boto3
import uuid
from datetime import datetime

region = 'us-east-1'
dynamodb = boto3.resource('dynamodb', region_name=region)
sns = boto3.client('sns', region_name=region)

# === SNS ===
def send_email_sns(subject, message, topic_arn):
    try:
        response = sns.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject=subject
        )
        return response
    except Exception as e:
        print("SNS Error:", e)
        return None

# === DYNAMODB ===
def put_item(table_name, item):
    table = dynamodb.Table(table_name)
    item['id'] = str(uuid.uuid4())
    table.put_item(Item=item)
    return item['id']

def get_item_by_key(table_name, key_name, key_value):
    table = dynamodb.Table(table_name)
    response = table.get_item(Key={key_name: key_value})
    return response.get('Item')

def query_items(table_name, key_name, key_value):
    table = dynamodb.Table(table_name)
    response = table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key(key_name).eq(key_value)
    )
    return response.get('Items', [])

def scan_table(table_name):
    table = dynamodb.Table(table_name)
    response = table.scan()
    return response.get('Items', [])
