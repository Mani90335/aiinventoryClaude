"""
cloudTrailHelper.py

Resolves "who owns this resource" and "when was it last touched", with a
priority order:
  1. A resource tag (Owner/CreatedBy/Team/...) — most trustworthy when present
  2. CloudTrail management events — best-effort fallback for the (common)
     case where the resource has no ownership tag at all
  3. "Unknown" — if neither source has an answer

On why CloudWatch is NOT used as an owner source: CloudWatch metrics
(Invocations, ConsumedInferenceUnits, etc.) carry no caller identity at
all — a metric datapoint says a resource WAS CALLED and roughly how much,
never BY WHOM. CloudWatch is used elsewhere in this codebase (see
cloudWatchHelper.py) purely for usage/last-invoked data, which is a
separate, complementary signal from ownership.
"""
from datetime import datetime, timedelta, timezone
from src.utils import logUtils

MODULE_NAME = __file__


def buildCreatorLookup(client, region, eventNames, lookbackDays):
    """
    Inside " + buildCreatorLookup.__name__ — builds a best-effort map of
    resource name -> (creator username, event time) from CloudTrail
    management events. Later events overwrite earlier ones, so the map
    ends up reflecting the MOST RECENT management action seen per name.

    `client` is a CloudTrail client already built via
    MarriottCSAO_utils.getAwsClient(config.SERVICE_NAME['CLOUDTRAIL'],
    accountId, region) — same getAwsClient flow used everywhere else in
    this codebase, rather than a cached session.
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + buildCreatorLookup.__name__)
    lookup = {}
    try:
        endTime = datetime.now(timezone.utc)
        startTime = endTime - timedelta(days=lookbackDays)

        for eventName in eventNames:
            try:
                paginator = client.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": eventName}],
                    StartTime=startTime, EndTime=endTime,
                ):
                    for e in page["Events"]:
                        user = e.get("Username", "Unknown")
                        ts = e["EventTime"]
                        for r in e.get("Resources", []):
                            name = r.get("ResourceName")
                            if not name:
                                continue
                            prev = lookup.get(name)
                            if prev is None or ts > prev[1]:
                                lookup[name] = (user, ts)
            except Exception as e:
                logUtils.logDebug(MODULE_NAME, f"[cloudtrail:{eventName}:{region}] {e}")

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)

    return lookup


def resolveOwnerAndLastUsed(resourceName, tags, creatorLookup, fallbackTime):
    """
    Inside " + resolveOwnerAndLastUsed.__name__ — prefers a tag-based
    owner over the CloudTrail-derived creator (a human-assigned Owner tag
    is more trustworthy than "whoever last called an API"), and prefers
    the most recent of the resource's own timestamp vs. the CloudTrail
    event time for "Last Used".
    """
    logUtils.logInfo(MODULE_NAME, "Inside " + resolveOwnerAndLastUsed.__name__)
    try:
        owner = None
        for key in ("Owner", "owner", "CreatedBy", "createdBy", "team", "Team"):
            if key in tags:
                owner = tags[key]
                break

        lastUsed = fallbackTime.isoformat() if fallbackTime else "Unknown"

        if resourceName in creatorLookup:
            ctUser, ctTime = creatorLookup[resourceName]
            if owner is None:
                # No tag at all — this is the fallback the team asked
                # for: CloudTrail becomes the owner source of last resort.
                owner = ctUser
                logUtils.logDebug(MODULE_NAME, f"No owner tag for {resourceName}; using CloudTrail creator {ctUser}")
            if fallbackTime is None or ctTime > fallbackTime:
                lastUsed = ctTime.isoformat()

        if owner is None:
            owner = "Unknown"

        return owner, lastUsed

    except Exception as e:
        logUtils.logError(MODULE_NAME, e)
        return "Unknown", "Unknown"
