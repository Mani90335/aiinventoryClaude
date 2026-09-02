"""
Filename: config.py
Contains hard coded strings and constants for the AI resource inventory
scanner. Follows the same shape as the CSAO remediation codebase's
config.py — plain constants, no logic.

PATCH NOTE (2026-09-03): removed the 'AI_INVENTORY_MONITORED_ACCOUNTS'
table key. Production only ever has ONE account-info table —
MARRIOTTCSAOSubAccountInfo — used both to find the master account
(accountType == 'master', see MarriottCSAO_utils.getMasterAccountId) and
now also to find every sub-account to scan. There is no second table in
production; inventing one here was incorrect and just meant extra setup
work (and an extra IAM grant) for no reason. Everything — master account
row AND sub-account rows — now lives in this one table.
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

# SINGLE account-info table, matching production exactly. Both the
# master-account lookup (getMasterAccountId, filters accountType ==
# 'master') and the sub-account-scan-scope lookup (getMonitoredSubAccounts,
# reads every row) point at this same table/key — there is only one.
TABLE_NAME = {
    'CSAO_MONITORED_SUB_ACCOUNTS': 'MARRIOTTCSAOSubAccountInfo',
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
Required DynamoDB table (single table, matching production):
  MARRIOTTCSAOSubAccountInfo
    - one row with accountType == 'master'            -> used by getMasterAccountId()
    - one row per sub-account to scan, each with:
        accountId, configuredRegions (list), configuredServices (list, optional)
      -> used by getMonitoredSubAccounts()
    A single row MAY be both (accountType == 'master' AND also carry
    configuredRegions/configuredServices) if you want the master account
    itself included in the scan — nothing in the code prevents that.

Required IAM permissions for SCAN_ROLE (TARGET_MGMT_ROLE) in every sub-account:
  sagemaker:List*, comprehend:List*, bedrock:List*, bedrock-agent:List*,
  bedrock:GetModelInvocationLoggingConfiguration, cloudwatch:ListMetrics,
  cloudwatch:GetMetricStatistics, cloudtrail:LookupEvents, sts:GetCallerIdentity,
  ec2:DescribeRegions   -- NEW: used to auto-discover an account's enabled
                            regions when its DynamoDB row has no
                            configuredRegions override (see accountOrchestrator
                            ._discoverAccountRegions)

Required IAM permissions for the MASTER account's Lambda execution role:
  sts:AssumeRole on arn:aws:iam::*:role/<TARGET_MGMT_ROLE>
  dynamodb:Scan, dynamodb:GetItem on MARRIOTTCSAOSubAccountInfo (in DYNAMO_DB_REGION
    AND every region listed in DYNAMO_DB_REGION_BACKUP_GT)
  s3:PutObject on OUTPUT_BUCKET
"""