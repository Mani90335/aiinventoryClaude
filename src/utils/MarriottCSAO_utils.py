"""
MarriottCSAO_utils.py

Shared AWS/DynamoDB helpers for the AI Inventory scanner. This is a
trimmed copy of the CSAO remediation codebase's MarriottCSAO_utils.py:

  KEPT, same code as the remediation version (per instruction) —
    getAwsClient, getAwsResourceClient, getMasterAccountId,
    recordTimeBasedException, getRegionCoordinates, getRegionNameFromCode

  REMOVED — remediation-only, not applicable to a discovery/scan Lambda:
    getRuleAlertInfo, getRuleConfigurations, getEmailFromArn

  NEW — getMonitoredSubAccounts(): AI Inventory needs to enumerate EVERY
    sub-account to scan in one run (a scheduled bulk scan), whereas
    S3Versioning only ever looks up ONE account per event (the account
    the triggering event came from). There's no "list all accounts"
    utility in the remediation codebase to reuse, so this is new — but
    built with the exact same DynamoDB access pattern (boto3.resource,
    Table(), try/except with backup-region retry) as every other
    DynamoDB call in this file.
"""
import boto3
from src.utils import logUtils
from src.config import config
from boto3.dynamodb.conditions import Attr

MODULE_NAME = __file__


# get AWS client in target account — SAME CODE as the remediation
# codebase's getAwsClient. accountId == getMasterAccountId() means this
# Lambda is already running in that account, so no assume-role hop is
# needed; every other account is reached via sts:AssumeRole.
def getAwsClient(client, accountId, awsRegion):
    try:
        if accountId == getMasterAccountId():
            serviceClient = boto3.client(client, region_name=awsRegion)
        else:
            stsClient = boto3.client('sts')
            roleName = config.TARGET_MGMT_ROLE
            sessionName = config.SESSION_NAME
            roleArn = f'arn:aws:iam::{accountId}:role/{roleName}'
            role = stsClient.assume_role(RoleArn=roleArn, RoleSessionName=sessionName)
            accessKey = role['Credentials']['AccessKeyId']
            secretKey = role['Credentials']['SecretAccessKey']
            sessionToken = role['Credentials']['SessionToken']
            serviceClient = boto3.client(client, region_name=awsRegion,
                                          aws_access_key_id=accessKey,
                                          aws_secret_access_key=secretKey,
                                          aws_session_token=sessionToken)
        return serviceClient

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


# get AWS resource client in target account — SAME CODE as the
# remediation codebase's getAwsResourceClient. Not currently called by
# any handler (every AWS call in this scanner uses the low-level client,
# not the resource API), but kept available for parity / future use —
# e.g. a future handler that wants DynamoDB-Resource-style item access.
def getAwsResourceClient(client, accountId, awsRegion):
    try:
        if accountId == getMasterAccountId():
            serviceClient = boto3.resource(client, region_name=awsRegion)

        else:
            stsClient = boto3.client('sts')
            roleName = config.TARGET_MGMT_ROLE
            sessionName = config.SESSION_NAME
            roleArn = f'arn:aws:iam::{accountId}:role/{roleName}'
            role = stsClient.assume_role(RoleArn=roleArn, RoleSessionName=sessionName)
            accessKey = role['Credentials']['AccessKeyId']
            secretKey = role['Credentials']['SecretAccessKey']
            sessionToken = role['Credentials']['SessionToken']
            serviceClient = boto3.resource(client, region_name=awsRegion,
                                            aws_access_key_id=accessKey,
                                            aws_secret_access_key=secretKey,
                                            aws_session_token=sessionToken)
        return serviceClient

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


# Function to capture any resources falling under Time-based exceptions —
# SAME CODE as the remediation codebase's recordTimeBasedException. Not
# called anywhere in the current scan flow (there's no "exception" concept
# for inventory discovery today), but kept per instruction so a future
# feature — e.g. "suppress an idle-resource flag for this bucket/endpoint
# for the next 30 days" — can reuse this without writing it from scratch.
def recordTimeBasedException(resource, ruleName, service, accountId, region, startTime, endTime):

    retry = config.RETRY_ATTEMPTS

    while retry >= 0:
        try:
            retry = retry - 1
            dynamoDbClient = boto3.client('dynamodb', region_name=config.DYNAMO_DB_REGION)
            response = dynamoDbClient.put_item(
                TableName=config.TRACK_TIME_BASED_EXCEPTION_TABLE,
                Item={
                    'uniqueIdentifier': {'S': resource + ' | ' + ruleName},
                    'resourceName': {'S': resource},
                    'accountId': {'S': accountId},
                    'ruleName': {'S': ruleName},
                    'region': {'S': region},
                    'service': {'S': service},
                    'startTime': {'S': str(startTime)},
                    'endTime': {'S': str(endTime)}
                }
            )

            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                logUtils.logInfo(MODULE_NAME, 'Time-based exception recorded successfully...')
                return

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            logUtils.logInfo(MODULE_NAME, 'Failed, Time-based exception not recorded ...')
            logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

            for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
                try:
                    dynamoDbClient = boto3.client('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])
                    response = dynamoDbClient.put_item(
                        TableName=config.TRACK_TIME_BASED_EXCEPTION_TABLE,
                        Item={
                            'uniqueIdentifier': {'S': resource + ' | ' + ruleName},
                            'resourceName': {'S': resource},
                            'accountId': {'S': accountId},
                            'ruleName': {'S': ruleName},
                            'region': {'S': region},
                            'service': {'S': service},
                            'startTime': {'S': str(startTime)},
                            'endTime': {'S': str(endTime)}
                        }
                    )

                    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                        logUtils.logInfo(MODULE_NAME, 'Time-based exception recorded successfully...')
                        break

                except Exception as e:
                    logUtils.logError(MODULE_NAME, e)
            return


# SAME CODE as the remediation codebase's getMasterAccountId — scans
# MARRIOTTCSAOSubAccountInfo (the EXISTING CSAO table, shared, not
# recreated here) for the one row where accountType == 'master'.
def getMasterAccountId():
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION)
        table = dynamodb.Table(config.TABLE_NAME['CSAO_MONITORED_SUB_ACCOUNTS'])
        response = table.scan(
            FilterExpression=Attr('accountType').eq('master')
        )
        masterAccountId = response['Items'][0]['accountId']

        return masterAccountId

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

        for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
            try:
                dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])

                table = dynamodb.Table(config.TABLE_NAME['CSAO_MONITORED_SUB_ACCOUNTS'])
                response = table.scan(
                    FilterExpression=Attr('accountType').eq('master')
                )
                masterAccountId = response['Items'][0]['accountId']
                break

            except Exception as e:
                logUtils.logError(MODULE_NAME, e)

        return masterAccountId


# NEW — analogous in shape to getMasterAccountId() above, but scans the
# AIInventoryMonitoredAccounts table (see config.py docstring for the
# expected item shape: accountId, scanEnabled, configuredRegions,
# configuredServices) instead of filtering for accountType == 'master'.
# Since this table only ever contains SUB-account rows, the master
# account is naturally excluded — no extra filtering needed.
def getMonitoredSubAccounts():
    try:
        dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION)
        table = dynamodb.Table(config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS'])
        response = table.scan(
            FilterExpression=Attr('scanEnabled').eq(True)
        )
        accounts = response['Items']

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression=Attr('scanEnabled').eq(True),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            accounts.extend(response['Items'])

        return accounts

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        logUtils.logInfo(MODULE_NAME, 'Trying another region ...')

        for backupTable in range(len(config.DYNAMO_DB_REGION_BACKUP_GT)):
            try:
                dynamodb = boto3.resource('dynamodb', region_name=config.DYNAMO_DB_REGION_BACKUP_GT[backupTable])
                table = dynamodb.Table(config.TABLE_NAME['AI_INVENTORY_MONITORED_ACCOUNTS'])
                response = table.scan(
                    FilterExpression=Attr('scanEnabled').eq(True)
                )
                accounts = response['Items']

                while 'LastEvaluatedKey' in response:
                    response = table.scan(
                        FilterExpression=Attr('scanEnabled').eq(True),
                        ExclusiveStartKey=response['LastEvaluatedKey']
                    )
                    accounts.extend(response['Items'])
                return accounts

            except Exception as e:
                logUtils.logError(MODULE_NAME, e)

        return []


# SAME CODE as the remediation codebase's getRegionCoordinates.
def getRegionCoordinates(region):

    coordinates = {
        "us-east-2": {"Latitude": "40.2253569", "Longitude": "-82.6881395", "Country": "United States of America"},
        "us-east-1": {"Latitude": "36.5615409", "Longitude": "-76.010467", "Country": "United States of America"},
        "us-west-1": {"Latitude": "34.1682408", "Longitude": "-117.3005188", "Country": "United States of America"},
        "us-west-2": {"Latitude": "43.9792797", "Longitude": "-120.737257", "Country": "United States of America"},
        "af-south-1": {"Latitude": "-33.928992", "Longitude": "18.417396", "Country": "South Africa"},
        "ap-east-1": {"Latitude": "22.2793278", "Longitude": "114.1628131", "Country": "China"},
        "ap-south-1": {"Latitude": "18.9387711", "Longitude": "72.8353355", "Country": "India"},
        "ap-northeast-3": {"Latitude": "34.7404526", "Longitude": "135.5232738", "Country": "Japan"},
        "ap-northeast-2": {"Latitude": "37.5666791", "Longitude": "126.9782914", "Country": "South Korea"},
        "ap-southeast-1": {"Latitude": "1.3408630000000001", "Longitude": "103.83039182212079", "Country": "Singapore"},
        "ap-southeast-2": {"Latitude": "-33.8548157", "Longitude": "151.2164539", "Country": "Australia"},
        "ap-northeast-1": {"Latitude": "35.6828387", "Longitude": "139.7594549", "Country": "Japan"},
        "ca-central-1": {"Latitude": "46.8928907", "Longitude": "-71.5253836", "Country": "Canada"},
        "cn-north-1": {"Latitude": "39.9020668", "Longitude": "116.718583", "Country": "China"},
        "cn-northwest-1": {"Latitude": "37.0000001", "Longitude": "105.9999999", "Country": "China"},
        "eu-central-1": {"Latitude": "50.1106444", "Longitude": "8.6820917", "Country": "Germany"},
        "eu-west-1": {"Latitude": "52.865196", "Longitude": "-7.9794599", "Country": "Ireland"},
        "eu-west-2": {"Latitude": "51.5073219", "Longitude": "-0.1276474", "Country": "United Kingdom"},
        "eu-south-1": {"Latitude": "45.4668", "Longitude": "9.1905", "Country": "Italy"},
        "eu-west-3": {"Latitude": "48.8566969", "Longitude": "2.3514616", "Country": "France"},
        "eu-north-1": {"Latitude": "59.3251172", "Longitude": "18.0710935", "Country": "Sweden"},
        "me-south-1": {"Latitude": "26.1551249", "Longitude": "50.5344606", "Country": "Bahrain"},
        "sa-east-1": {"Latitude": "-23.5506507", "Longitude": "-46.6333824", "Country": "Brazil"},
        "global": {"Latitude": "NA", "Longitude": "NA", "Country": "Global"},
    }

    return coordinates.get(region, {"Latitude": "NA", "Longitude": "NA", "Country": "Unknown"})


# SAME CODE as the remediation codebase's getRegionNameFromCode.
def getRegionNameFromCode():
    regionMapping = {
        "us-east-1": "North Virginia", "us-east-2": "Ohio", "us-west-1": "North California",
        "us-west-2": "Oregon", "ca-central-1": "Canada", "eu-west-1": "Ireland",
        "eu-central-1": "Frankfurt", "eu-west-2": "London", "eu-west-3": "Paris",
        "eu-north-1": "Stockholm", "ap-northeast-1": "Tokyo", "ap-northeast-2": "Seoul",
        "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney", "ap-south-1": "Mumbai",
        "sa-east-1": "São Paulo", "af-south-1": "Cape Town", "ap-east-1": "Hong Kong",
        "ap-northeast-3": "Osaka", "eu-south-1": "Milan", "me-south-1": "Bahrain",
        "global": "Global",
    }
    return regionMapping
