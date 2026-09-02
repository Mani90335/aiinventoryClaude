"""
accountOrchestrator.py

Runs the full scan for ONE sub-account. Unlike the remediation codebase
(where one Lambda invocation always concerns exactly one account, taken
from the triggering event), this scanner must cover EVERY monitored
account in one run — so lambda_function.py calls scanAccount() once per
item returned by MarriottCSAO_utils.getMonitoredSubAccounts().

Region and service scope come from the account's own DynamoDB row
(configuredRegions / configuredServices) — this is the "same DynamoDB
flow" as the account-config lookups elsewhere in this codebase, applied
to decide WHERE to scan, not just WHETHER a rule is enabled.
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
      — expected shape: {accountId, scanEnabled, configuredRegions, configuredServices}

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
        regions = accountInfo.get("configuredRegions") or []
        services = accountInfo.get("configuredServices") or config.SERVICES

        if not regions:
            logUtils.logInfo(MODULE_NAME, f"[{accountId}] No configuredRegions in DynamoDB — skipping account")
            result["errors"].append({
                "account": accountId, "region": None, "source": "accountOrchestrator",
                "error_type": "NoConfiguredRegions",
                "error": f"AIInventoryMonitoredAccounts item for {accountId} has no configuredRegions",
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
