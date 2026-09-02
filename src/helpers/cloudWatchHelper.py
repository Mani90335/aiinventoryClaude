"""
cloudWatchHelper.py

Pulls the "Invocations"-style CloudWatch metric AWS publishes
automatically (no configuration required) for SageMaker and Bedrock. This
reliably answers "is this actually in use" and "when was it last called"
— but, as noted in cloudTrailHelper.py, it can never say WHO called it, so
it is never used as an owner source, only a usage source.
"""
from datetime import datetime, timedelta, timezone
from src.utils import logUtils

MODULE_NAME = __file__


def getCloudWatchUsage(client, region, namespace, metricName, dimensionName, lookbackDays):
    """
    Inside " + getCloudWatchUsage.__name__ — returns
    {dimensionValue: {invocation_count, last_invocation_time}} for every
    distinct dimension value CloudWatch has data for. CloudWatch only
    lists metrics that received datapoints, so a resource with zero calls
    simply won't appear here — that absence means "genuinely idle," not
    "unknown".

    `client` is a CloudWatch client already built via
    MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDWATCH'],
    accountId, region) — same getAwsClient flow used everywhere else.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + getCloudWatchUsage.__name__)
    results = {}
    try:
        seen = set()

        try:
            for page in client.get_paginator("list_metrics").paginate(Namespace=namespace, MetricName=metricName):
                for m in page["Metrics"]:
                    dims = {d["Name"]: d["Value"] for d in m.get("Dimensions", [])}
                    key = dims.get(dimensionName)
                    if key:
                        seen.add(key)
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return results

        endTime = datetime.now(timezone.utc)
        startTime = endTime - timedelta(days=lookbackDays)

        for key in seen:
            try:
                resp = client.get_metric_statistics(
                    Namespace=namespace, MetricName=metricName,
                    Dimensions=[{"Name": dimensionName, "Value": key}],
                    StartTime=startTime, EndTime=endTime, Period=86400, Statistics=["Sum"],
                )
                datapoints = resp.get("Datapoints", [])
                total = sum(dp["Sum"] for dp in datapoints)
                lastTs = max((dp["Timestamp"] for dp in datapoints), default=None)
                results[key] = {
                    f"invocation_count_last_{lookbackDays}d": int(total),
                    "last_invocation_time": lastTs.isoformat() if lastTs else "No invocations in lookback window",
                }
            except Exception as e:
                logUtils.logDebug(MODULE_NAME, f"[cloudwatch:{namespace}:{metricName}:{key}:{region}] {e}")

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)

    return results
