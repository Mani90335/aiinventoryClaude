"""
tagHelper.py

Read-only tag lookups, one function per service, in the same shape as
the remediation codebase's taghelpers3.py getTags(): a single try/except,
a logDebug fallback message on failure, always returns a value (never
raises) so a missing/failed tag call never breaks a scan.

Only getTags-equivalents are kept. addTagsForReset() and addTags() from
the remediation codebase are NOT ported here — this scanner only ever
reads tags, it never writes/removes them, so those two functions have
no use in this codebase.
"""
from src.utils import logUtils

MODULE_NAME = __file__


def getSageMakerTags(client, resourceArn):
    """resourceArn: the SageMaker resource's ARN (endpoint, domain, etc.)."""
    try:
        tagResponse = client.list_tags(ResourceArn=resourceArn)
        return {t['Key']: t['Value'] for t in tagResponse.get('Tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}


def getComprehendTags(client, resourceArn):
    try:
        tagResponse = client.list_tags_for_resource(ResourceArn=resourceArn)
        return {t['Key']: t['Value'] for t in tagResponse.get('Tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}


def getBedrockTags(client, resourceArn):
    try:
        tagResponse = client.list_tags_for_resource(resourceARN=resourceArn)
        return {t['key']: t['value'] for t in tagResponse.get('tags', [])}
    except Exception as e:
        logUtils.logDebug(MODULE_NAME, f"Unable to fetch Tags or No tags found for {resourceArn}: {e}")
        return {}
