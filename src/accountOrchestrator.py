"""
accountOrchestrator.py

Runs the full scan for ONE sub-account. Unlike the remediation codebase
(where one Lambda invocation always concerns exactly one account, taken
from the triggering event), this scanner must cover EVERY monitored
account in one run — so lambda_function.py calls scanAccount() once per
item returned by MarriottCSAO_utils.getMonitoredSubAccounts().

PATCH NOTE (2026-09-03): region scope no longer REQUIRES a
'configuredRegions' attribute in DynamoDB. S3Versioning.py (and every
other event-driven remediation handler in production) never stores a
region list per account at all — it always pulls the region straight off
the triggering CloudTrail/Config event. AI Inventory has no triggering
event to read a region from (it's a scheduled bulk scan, not
event-driven), so it can't copy that exactly — but it CAN match the same
underlying philosophy: don't require a manual per-account setup step.
'configuredRegions' in DynamoDB is now an OPTIONAL override (handy for
narrowing a test run to one region) rather than a hard requirement; when
it's absent, regions are auto-discovered per account via
ec2:DescribeRegions, the same way the very first version of this scanner
worked. An account with zero enabled regions (or a broken EC2 permission)
is still skipped and logged — but that's now a genuine "couldn't
discover any regions" case, not "forgot to set an attribute in DynamoDB".
"""
from src.utils import logUtils, MarriottCSAO_utils
from src.helpers import cloudTrailHelper, cloudWatchHelper
from src.handlers.sagemakerHandler import SageMakerHandler
from src.handlers.comprehendHandler import ComprehendHandler
from src.handlers.bedrockHandler import BedrockHandler
from src.config import config

MODULE_NAME = __file__

# Add a new service by (1) writing a new leaf handler class in
# src/handlers/, same as adding a new rule handler in the remediation
# codebase, and (2) registering it here.
HANDLER_CLASSES = {
    "sagemaker": SageMakerHandler,
    "comprehend": ComprehendHandler,
    "bedrock": BedrockHandler,
}


def scanAccount(accountInfo):
    """
    accountInfo: one item from MarriottCSAO_utils.getMonitoredSubAccounts()
      — expected shape: {accountId, configuredRegions?, configuredServices?}
      (configuredRegions / configuredServices are both OPTIONAL overrides;
      see _discoverAccountRegions() and config.SERVICES for the defaults
      used when they're absent.)

    Returns:
      {
        "account_id": ...,
        "rows": {"sagemaker": [...], "comprehend": [...], "bedrock": [...]},
        "bedrock_model_usage": [...],
        "bedrock_logging_status": [...],
        "errors": [...],
      }
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + scanAccount.__name__)

    accountId = str(accountInfo.get("accountId"))
    result = {
        "account_id": accountId,
        "rows": {name: [] for name in HANDLER_CLASSES},
        "bedrock_model_usage": [],
        "bedrock_logging_status": [],
        "errors": [],
    }

    try:
        services = accountInfo.get("configuredServices") or config.SERVICES

        # configuredRegions is an OPTIONAL manual override (e.g. to
        # narrow a test run to one region). When absent, auto-discover
        # every enabled region for this account instead of requiring it
        # to be set in DynamoDB.
        regions = accountInfo.get("configuredRegions")
        if not regions:
            logUtils.logDebug(
                MODULE_NAME,
                f"[{accountId}] No configuredRegions override — auto-discovering enabled regions"
            )
            regions = _discoverAccountRegions(accountId)

        if not regions:
            logUtils.logInfo(
                MODULE_NAME,
                f"[{accountId}] Could not determine any region to scan (no override, "
                "and ec2:DescribeRegions returned nothing/failed) — skipping account"
            )
            result["errors"].append({
                "account": accountId, "region": None, "source": "accountOrchestrator",
                "error_type": "NoRegionsResolved",
                "error": f"No configuredRegions override and region auto-discovery found "
                         f"nothing for {accountId} — check ec2:DescribeRegions permission "
                         f"on {config.TARGET_MGMT_ROLE} in that account.",
            })
            return result

        logUtils.logDebug(MODULE_NAME, f"[{accountId}] scanning regions={regions} services={services}")

        for region in regions:
            for service in services:
                handlerCls = HANDLER_CLASSES.get(service)
                if handlerCls is None:
                    logUtils.logInfo(MODULE_NAME, f"Unknown service '{service}' in configuredServices — skipping")
                    continue

                try:
                    ctClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDTRAIL'], accountId, region)
                    creatorLookup = cloudTrailHelper.buildCreatorLookup(
                        ctClient, region, handlerCls.eventNames, config.LOOKBACK_DAYS
                    ) if ctClient else {}

                    handler = handlerCls(service, accountId, region, creatorLookup)
                    result["rows"][service].extend(handler.scan())
                    result["errors"].extend(handler.errors)

                    if service == "bedrock":
                        result["bedrock_logging_status"].append(handler.getLoggingStatus())
                        _mergeBedrockUsage(accountId, region, result)

                    if service == "sagemaker":
                        _mergeSageMakerUsage(accountId, region, result)

                    if service == "comprehend":
                        _mergeComprehendUsage(accountId, region, result)

                except Exception as e:
                    logUtils.logError(MODULE_NAME, e)
                    result["errors"].append({
                        "account": accountId, "region": region, "source": f"{service}:handler",
                        "error_type": type(e).__name__, "error": str(e),
                    })

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        result["errors"].append({
            "account": accountId, "region": None, "source": "accountOrchestrator",
            "error_type": type(e).__name__, "error": str(e),
        })

    return result


def _discoverAccountRegions(accountId):
    """
    Inside " + _discoverAccountRegions.__name__ — returns every region
    enabled for this account, via ec2:DescribeRegions (AllRegions=False
    returns only OPTED-IN/enabled regions, same call used by the very
    first version of this scanner). Uses the same getAwsClient flow as
    every other AWS call here, so it transparently assumes into the
    sub-account if needed. Always returns a list (never raises) — a
    failure here is just "no regions discovered", handled by the caller.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + _discoverAccountRegions.__name__)
    try:
        ec2Client = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['EC2'], accountId, 'us-east-1')
        if not ec2Client:
            return []
        response = ec2Client.describe_regions(AllRegions=False)
        return sorted(r['RegionName'] for r in response['Regions'])
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        return []


# ---------------------------------------------------------------------
# CloudWatch usage merges
# ---------------------------------------------------------------------

def _mergeBedrockUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeBedrockUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/Bedrock", "Invocations", "ModelId", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for modelId, u in usage.items():
            result["bedrock_model_usage"].append({
                "model_id": modelId, "region": region, "account": accountId, **u
            })
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


def _mergeSageMakerUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeSageMakerUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/SageMaker", "Invocations", "EndpointName", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for row in result["rows"]["sagemaker"]:
            if row["Type"] == "Endpoint" and row["Region"] == region and row["Resource"] in usage:
                row["Details"].update(usage[row["Resource"]])
                row["Last Used"] = usage[row["Resource"]]["last_invocation_time"]
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)


def _mergeComprehendUsage(accountId, region, result):
    logUtils.logInfo(MODULE_NAME, "Inside " + _mergeComprehendUsage.__name__)
    try:
        cwClient = MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'], accountId, region)
        if not cwClient:
            return
        usage = cloudWatchHelper.getCloudWatchUsage(
            cwClient, region, "AWS/Comprehend", "ConsumedInferenceUnits", "EndpointArn", config.CLOUDWATCH_LOOKBACK_DAYS
        )
        for row in result["rows"]["comprehend"]:
            if row["Type"] != "Endpoint" or row["Region"] != region:
                continue
            arn = row["Details"].get("endpoint_arn")
            if arn and arn in usage:
                row["Details"].update(usage[arn])
                row["Last Used"] = usage[arn]["last_invocation_time"]
    except Exception as e:
        logUtils.logError(MODULE_NAME, e)