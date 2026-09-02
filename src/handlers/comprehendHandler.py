"""
comprehendHandler.py
Leaf class for Comprehend — batch jobs, custom Entity Recognizers, and
real-time custom Endpoints.
"""
from src.utils import logUtils
from src.utils.AIInventoryEventHandler import AIInventoryEventHandlerAWSService
from src.helpers import tagHelper
from src.config import config

MODULE_NAME = __file__


class ComprehendHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['COMPREHEND']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanBatchJobs())
            rows.extend(self._scanEntityRecognizers())
            rows.extend(self._scanEndpoints())
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    def _scanBatchJobs(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanBatchJobs.__name__)
        rows = []
        jobCalls = {
            "DocumentClassificationJob": self.client.list_document_classification_jobs,
            "EntitiesDetectionJob": self.client.list_entities_detection_jobs,
            "SentimentDetectionJob": self.client.list_sentiment_detection_jobs,
            "KeyPhrasesDetectionJob": self.client.list_key_phrases_detection_jobs,
            "PiiEntitiesDetectionJob": self.client.list_pii_entities_detection_jobs,
        }
        for jobType, call in jobCalls.items():
            try:
                resp = call()
                listKey = [k for k in resp if k.endswith("JobPropertiesList")]
                jobs = resp[listKey[0]] if listKey else []
                for j in jobs:
                    name = j.get("JobName") or j.get("JobId")
                    submitTime = j.get("SubmitTime")
                    endTime = j.get("EndTime", submitTime)
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, endTime)
                    rows.append(self.makeRow(name, jobType, owner, lastUsed, {
                        "status": j.get("JobStatus"),
                        "submitted": submitTime.isoformat() if submitTime else None,
                    }))
            except Exception as e:
                self.logScanError(jobType, e)
        return rows

    # Not a batch job — a custom-trained model.
    def _scanEntityRecognizers(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEntityRecognizers.__name__)
        rows = []
        try:
            for r in self.client.list_entity_recognizers().get("EntityRecognizerPropertiesList", []):
                name = r["EntityRecognizerArn"].split("/")[-1]
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, r.get("EndTime", r.get("SubmitTime")))
                rows.append(self.makeRow(name, "EntityRecognizer", owner, lastUsed, {
                    "status": r.get("Status"),
                }))
        except Exception as e:
            self.logScanError("entity_recognizers", e)
        return rows

    # Real-time custom Endpoints — the only Comprehend resource type with
    # a real CloudWatch usage metric (ConsumedInferenceUnits).
    def _scanEndpoints(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanEndpoints.__name__)
        rows = []
        try:
            for page in self.client.get_paginator("list_endpoints").paginate():
                for ep in page.get("EndpointPropertiesList", []):
                    endpointArn = ep.get("EndpointArn", "")
                    name = endpointArn.split("/")[-1] if endpointArn else "unknown-endpoint"
                    tags = tagHelper.getComprehendTags(self.client, endpointArn) if endpointArn else {}
                    owner, lastUsed = self.resolveOwnerAndLastUsed(
                        name, tags, ep.get("LastModifiedTime", ep.get("CreationTime"))
                    )
                    rows.append(self.makeRow(name, "Endpoint", owner, lastUsed, {
                        "endpoint_arn": endpointArn,
                        "status": ep.get("Status"),
                        "model_arn": ep.get("ModelArn"),
                        "desired_inference_units": ep.get("DesiredInferenceUnits"),
                        "current_inference_units": ep.get("CurrentInferenceUnits"),
                        "created": str(ep.get("CreationTime")),
                        "tags": tags,
                    }))
        except Exception as e:
            self.logScanError("list_endpoints", e)
        return rows
