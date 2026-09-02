"""
s3OutputHelper.py

Writes scan output to the master account's S3 bucket. Uses
MarriottCSAO_utils.getAwsClient — same flow as every other AWS call in
this codebase — with the MASTER account's own ID, so it always writes
using the master account's own credentials directly (accountId ==
getMasterAccountId() inside getAwsClient means no assume-role hop).
Every sub-account is only ever read from; only the master account ever
writes, so no cross-account bucket policy is required.
"""
import json
from src.utils import logUtils, MarriottCSAO_utils
from src.config import config

MODULE_NAME = __file__


def writeJsonToS3(masterAccountId, key, data):
    logUtils.logInfo(MODULE_NAME, "Inside " + writeJsonToS3.__name__)
    try:
        s3Client = MarriottCSAO_utils.getAwsClient(
            config.SERVICE_NAME['S3'], masterAccountId, config.OUTPUT_REGION
        )
        s3Client.put_object(
            Bucket=config.OUTPUT_BUCKET, Key=key,
            Body=json.dumps(data, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        logUtils.logDebug(MODULE_NAME, f"Wrote s3://{config.OUTPUT_BUCKET}/{key}")
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
