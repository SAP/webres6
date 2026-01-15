# Set up S3 test with localstack

Start localstack as docker container
```bash
docker run --name s3 --rm -p 4566:4566 localstack/localstack:s3-latest
```
Create S3 Bucket
```bash
aws s3 --region eu-west-1 --endpoint http://127.0.0.1:4566 mb s3://webres6-tes
```

Set CORS policy
```bash
cat > s3-localstack-cors.json <<EOF
{
    "CORSRules": [
      {
        "AllowedOrigins": ["http://localhost:6400", "http://localhost:6480"],
        "AllowedMethods": ["GET", "HEAD"],
        "AllowedHeaders": ["*"],
        "ExposeHeaders": ["ETag", "Expires"],
        "MaxAgeSeconds": 38400
      }
    ]
}
EOF
aws s3api put-bucket-cors --region eu-west-1 --endpoint http://127.0.0.1:4566 --bucket webres6-test --cors-configuration file://s3-localstack-cors.json
```

Start Valkey
```bash
docker-compose up -d valkey
```

Start the API server
```bash
cd api
source ./.venv/bin/activate
S3_ENDPOINT="http://127.0.0.1:4566" S3_BUCKET="webres6-test" VALKEY_URL="valkey://localhost:6379/0" ./webres6-api.py
```

