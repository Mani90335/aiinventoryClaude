"""
Filename: config.py
Contains hard coded strings and constants for the AI resource inventory
scanner. Follows the same shape as the CSAO remediation codebase's
config.py — plain constants, no logic.
"""
import os

GENERIC_ERROR_STATUS_CODE = 400
GENERIC_ERROR_MESSAGE = "UNKNOWN ERROR"
RETRY_ATTEMPTS = 10

DYNAMO_DB_REGION = 'us-east-1'
DYNAMO_DB_REGION_BACKUP_GT = ['us-west-2']

SERVICE_NAME = {
    'STS': 'sts',
    'IAM': 'iam',
    'EC2': 'ec2',
    'S3': 's3',
    'SAGEMAKER': 'sagemaker',
    'COMPREHEND': 'comprehend',
    'BEDROCK': 'bedrock',
    'BEDROCK_AGENT': 'bedrock-agent',
    'CLOUDWATCH': 'cloudwatch',
    'CLOUDTRAIL': 'cloudtrail',
    'ORGANIZATIONS': 'organizations',
}

# CloudTrail management-event names used to resolve "who created / last
# touched this resource" per service, when tags don't carry an Owner.
# Kept centrally here, same as EVENT_NAME in the CSAO config.py, rather
# than scattered across each handler.
EVENT_NAME = {
    'SAGEMAKER': [
        'CreateEndpoint', 'UpdateEndpoint', 'CreateTrainingJob', 'CreateNotebookInstance',
        'CreateDomain', 'CreateSpace', 'CreateApp', 'CreateProcessingJob', 'CreateCodeRepository',
    ],
    'COMPREHEND': [
        'StartDocumentClassificationJob', 'StartEntitiesDetectionJob',
        'StartSentimentDetectionJob', 'StartKeyPhrasesDetectionJob',
        'StartPiiEntitiesDetectionJob', 'CreateEntityRecognizer', 'CreateEndpoint',
    ],
    'BEDROCK': [
        'CreateModelCustomizationJob', 'CreateProvisionedModelThroughput',
        'CreateAgent', 'CreateAgentAlias', 'CreateKnowledgeBase',
    ],
}

TARGET_MGMT_ROLE = 'AWSCloudFormationStackSetExecutionRole'
SESSION_NAME = 'AIInventoryScan'

TABLE_NAME = {
    'CSAO_MONITORED_SUB_ACCOUNTS': 'MARRIOTTCSAOSubAccountInfo',   # existing CSAO table — master-account lookup only
    'AI_INVENTORY_MONITORED_ACCOUNTS': 'AIInventoryMonitoredAccounts',  # new — which sub-accounts/regions/services to scan
}

# Used only by recordTimeBasedException (kept for parity — see that
# function's docstring; not called anywhere in the current scan flow).
TRACK_TIME_BASED_EXCEPTION_TABLE = 'CSAOTimeBasedExceptions'

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET")
OUTPUT_PREFIX = os.environ.get("OUTPUT_PREFIX", "ai-resource-inventory")
OUTPUT_REGION = os.environ.get("OUTPUT_REGION", "us-east-1")

# ---------------------------------------------------------------------
# Services scanned when an account's DynamoDB row doesn't specify its own
# configuredServices list.
# ---------------------------------------------------------------------
SERVICES = ['sagemaker', 'comprehend', 'bedrock']

# ---------------------------------------------------------------------
# Lookback windows
# ---------------------------------------------------------------------
LOOKBACK_DAYS = int(os.environ.get("LOOKBACK_DAYS", "90"))
CLOUDWATCH_LOOKBACK_DAYS = int(os.environ.get("CLOUDWATCH_LOOKBACK_DAYS", "30"))

MAX_CONCURRENT_ACCOUNTS = int(os.environ.get("MAX_CONCURRENT_ACCOUNTS", "5"))

"""
Required DynamoDB tables (see module docstring / helper functions for shape):
  MARRIOTTCSAOSubAccountInfo    -- existing CSAO table, one row with accountType='master'
  AIInventoryMonitoredAccounts  -- one row per sub-account to scan:
                                    { accountId, scanEnabled, configuredRegions, configuredServices }

Required IAM permissions for SCAN_ROLE (TARGET_MGMT_ROLE) in every sub-account:
  sagemaker:List*, comprehend:List*, bedrock:List*, bedrock-agent:List*,
  bedrock:GetModelInvocationLoggingConfiguration, cloudwatch:ListMetrics,
  cloudwatch:GetMetricStatistics, cloudtrail:LookupEvents, sts:GetCallerIdentity

Required IAM permissions for the MASTER account's Lambda execution role:
  sts:AssumeRole on arn:aws:iam::*:role/<TARGET_MGMT_ROLE>
  dynamodb:GetItem, dynamodb:Scan on MARRIOTTCSAOSubAccountInfo and AIInventoryMonitoredAccounts
  s3:PutObject on OUTPUT_BUCKET
"""
