import os
import tempfile
from pathlib import Path, PurePosixPath

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class LocalStorage:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, key):
        parts = PurePosixPath(key)
        if parts.is_absolute() or ".." in parts.parts or "\\" in key:
            raise ValueError("Invalid object key")
        result = (self.root / key).resolve()
        if not result.is_relative_to(self.root):
            raise ValueError("Invalid object key")
        return result

    def put(self, key, data):
        path = self.path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def get(self, key):
        return self.path(key).read_bytes()

    def delete(self, key):
        self.path(key).unlink(missing_ok=True)

    def size(self, key):
        return self.path(key).stat().st_size

    def healthy(self):
        if not self.root.is_dir() or not os.access(self.root, os.R_OK | os.W_OK):
            raise OSError("Storage unavailable")


class S3Storage:
    def __init__(self, settings):
        self.bucket = settings.s3_bucket_name
        self.client = boto3.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.s3_endpoint_url,
            config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2}),
        )

    def put(self, key, data):
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType="application/octet-stream")

    def get(self, key):
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        try:
            return response["Body"].read()
        finally:
            response["Body"].close()

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def size(self, key):
        try:
            return self.client.head_object(Bucket=self.bucket, Key=key)["ContentLength"]
        except ClientError as error:
            if error.response["Error"]["Code"] in {"404", "NoSuchKey", "NotFound"}:
                raise FileNotFoundError(key) from error
            raise

    def healthy(self):
        self.client.head_bucket(Bucket=self.bucket)


def make_storage(settings):
    return LocalStorage(settings.storage_path) if settings.storage_backend == "local" else S3Storage(settings)
