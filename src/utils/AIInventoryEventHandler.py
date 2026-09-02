"""
AIInventoryEventHandler.py

Same three-layer inheritance pattern as the remediation codebase's
MARRIOTTCSAOEventHandler.py, adapted for discovery instead of
remediation:

  AIInventoryResourceHandler        (base — the blank template)
    -> AIInventoryEventHandlerAWS       (fills in AWS-specific plumbing)
      -> AIInventoryEventHandlerAWSService  (adds a default payload hook)
        -> <service>Handler (in src/handlers/) -- the leaf class, one per
           AWS service, the ONLY place that fills in scan()

Where this differs from the remediation handler, and why:
  - isRuleViolated()/remediate()/handleViolation() have no equivalent
    here — there is no "violation" to detect and fix, only resources to
    LIST. Their replacement is scan().
  - getAccountRuleConfigurations() (a DynamoDB lookup keyed on ruleName)
    has no equivalent either — per-account scan configuration (which
    regions/services) is read ONCE, up front, by accountOrchestrator.py
    via MarriottCSAO_utils.getMonitoredSubAccounts(), and handed to every
    handler instance rather than each handler re-fetching it. getAccountInfo()
    is kept as a stub for structural parity, same as the remediation
    codebase's own commented-out getAccountInfo().
  - createViolationEvent() has no equivalent — this scanner writes
    results to S3 (see s3OutputHelper.py), it doesn't publish an
    EventBridge alert per finding. getResourcePayload() is kept as the
    same kind of small, overridable hook as getEventCustomPayload() was,
    for a future leaf class that wants to attach extra fields per row.

To extend this in the future with a new AWS service to inventory: write
ONE new leaf class in src/handlers/ that extends
AIInventoryEventHandlerAWSService and implements scan() — everything
else (getting a client in the right account, logging, error collection)
is inherited, exactly like adding a new rule to the remediation codebase
only requires a new leaf class implementing isRuleViolated()/remediate().
"""
from src.utils import logUtils, MarriottCSAO_utils
from src.helpers import cloudTrailHelper
from src.config import config

MODULE_NAME = __file__


class AIInventoryResourceHandler:

    def __init__(self, service, accountId, region, creatorLookup=None):
        self.service = service
        self.accountId = accountId
        self.region = region
        self.creatorLookup = creatorLookup or {}
        self.client = self.getClient()
        self.accountInfo = self.getAccountInfo()
        self.retryAttempts = config.RETRY_ATTEMPTS
        # Per-handler error list, collected by accountOrchestrator.py into
        # the run-wide summary — same "don't let one failure kill the
        # whole run" intent as the retry/logError pattern in the
        # remediation handlers, just accumulated instead of retried,
        # since a failed LIST call has nothing sensible to retry against.
        self.errors = []

    def getClient(self):
        raise NotImplementedError

    def getAccountInfo(self):
        raise NotImplementedError

    def scan(self):
        raise NotImplementedError

    def getResourcePayload(self):
        raise NotImplementedError

    # -- Shared helpers available to every leaf class ---------------------

    def resolveOwnerAndLastUsed(self, resourceName, tags, fallbackTime):
        return cloudTrailHelper.resolveOwnerAndLastUsed(resourceName, tags, self.creatorLookup, fallbackTime)

    def makeRow(self, resource, resourceType, owner, lastUsed, details):
        try:
            regionName = MarriottCSAO_utils.getRegionNameFromCode().get(self.region, self.region)
            return {
                "Resource": resource,
                "Type": resourceType,
                "Region": self.region,
                "RegionName": regionName,
                "Account": self.accountId,
                "Owner": owner,
                "Last Used": lastUsed,
                "Details": details,
            }
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return {
                "Resource": resource, "Type": resourceType, "Region": self.region,
                "Account": self.accountId, "Owner": owner, "Last Used": lastUsed, "Details": details,
            }

    def logScanError(self, source, ex):
        msg = str(ex)
        logUtils.logError(MODULE_NAME, f"[{self.service}:{source}:{self.region}] {msg}")
        self.errors.append({
            "account": self.accountId,
            "region": self.region,
            "source": f"{self.service}:{source}",
            "error_type": type(ex).__name__,
            "error": msg,
        })


class AIInventoryEventHandlerAWS(AIInventoryResourceHandler):

    def getClient(self):
        try:
            logUtils.logDebug(MODULE_NAME, "getting client...")
            return MarriottCSAO_utils.getAwsClient(self.service, self.accountId, self.region)
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)

    def getAccountInfo(self):
        # Stubbed, same as the remediation codebase's own getAccountInfo()
        # (also commented out / a no-op there) — kept for structural
        # parity rather than deleted, so a future need (e.g. surfacing
        # account alias/owner metadata per row) has an obvious place to
        # implement it without restructuring the class chain.
        try:
            logUtils.logDebug(MODULE_NAME, "getAccountInfo not implemented for AI Inventory")
            return None
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)


class AIInventoryEventHandlerAWSService(AIInventoryEventHandlerAWS):

    def __init__(self, service, accountId, region, creatorLookup=None):
        super().__init__(service, accountId, region, creatorLookup)

    # Override this wherever needed in a leaf class, same as
    # getEventCustomPayload() in the remediation codebase.
    def getResourcePayload(self):
        try:
            return {'-': '-'}
        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
