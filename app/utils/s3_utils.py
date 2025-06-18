import boto3
import os
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# Initialize S3 client
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

def upload_to_s3(key: str, data: bytes, user_id: int):
    """
    Upload encrypted data to S3 under user-specific path
    """
    full_key = f"{user_id}/{key}"
    s3.put_object(Bucket=S3_BUCKET_NAME, Key=full_key, Body=data)
    print(f"✅ Uploaded {full_key} to S3")

def download_from_s3(key: str, user_id: int) -> bytes:
    """
    Download an object from S3 using user-specific path
    """
    full_key = f"{user_id}/{key}"
    response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=full_key)
    return response['Body'].read()

def delete_from_s3(key: str, user_id: int):
    """
    Delete a specific object from S3 under user-specific path
    """
    full_key = f"{user_id}/{key}"
    s3.delete_object(Bucket=S3_BUCKET_NAME, Key=full_key)
    print(f"🗑 Deleted {full_key} from S3")

def get_file_size_s3(key: str) -> int:
    """
    Return the size of a file in bytes from S3
    """
    try:
        obj = s3.head_object(Bucket=S3_BUCKET_NAME, Key=key)
        return obj['ContentLength']
    except Exception as e:
        print(f"❌ Could not get size for {key}: {e}")
        return 0
