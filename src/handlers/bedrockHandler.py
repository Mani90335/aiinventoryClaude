"""
bedrockHandler.py
Leaf class for Bedrock — Custom Models, Provisioned Throughput, Agents,
Agent Aliases, Knowledge Bases, plus the account/region's invocation-
logging config. Deliberately does NOT list Foundation Models
(bedrock:ListFoundationModels) — that's AWS's built-in catalog, identical
across every account, not something this account created or used.

Needs a second client — bedrock-agent — for Agents/Aliases/Knowledge
Bases, which self.client (built from self.service = 'bedrock' by the
base class) doesn't cover. Built the same way, via
MarriottCSAO_utils.getAwsClient, just for a different service name.
"""
from src.utils import logUtils, MarriottCSAO_utils
from src.utils.AIInventoryEventHandler import AIInventoryEventHandlerAWSService
from src.config import config

MODULE_NAME = __file__


class BedrockHandler(AIInventoryEventHandlerAWSService):

    eventNames = config.EVENT_NAME['BEDROCK']

    def scan(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self.scan.__name__)
        rows = []
        try:
            rows.extend(self._scanCustomModels())
            rows.extend(self._scanProvisionedThroughput())

            bedrockAgentClient = MarriottCSAO_utils.getAwsClient(
                config.SERVICE_NAME['BEDROCK_AGENT'], self.accountId, self.region
            )
            if bedrockAgentClient:
                agentRows, agentIds = self._scanAgents(bedrockAgentClient)
                rows.extend(agentRows)
                rows.extend(self._scanAgentAliases(bedrockAgentClient, agentIds))
                rows.extend(self._scanKnowledgeBases(bedrockAgentClient))
            else:
                self.logScanError("bedrock-agent:client", Exception("getAwsClient returned None"))

            rows.extend(self._scanLoggingConfig())
        except Exception as e:
            self.logScanError("scan", e)
        return rows

    def getLoggingStatus(self):
        """Account/region-level flag for the run summary — separate from
        the per-resource logging-config row scan() also appends."""
        logUtils.logInfo(MODULE_NAME, "Inside " + self.getLoggingStatus.__name__)
        try:
            cfg = self.client.get_model_invocation_logging_configuration().get("loggingConfig", {})
            return {"account": self.accountId, "region": self.region, "invocation_logging_enabled": bool(cfg)}
        except Exception as e:
            self.logScanError("logging_status", e)
            return {"account": self.accountId, "region": self.region,
                     "invocation_logging_enabled": False, "error": str(e)}

    def _scanCustomModels(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanCustomModels.__name__)
        rows = []
        try:
            for m in self.client.list_custom_models().get("modelSummaries", []):
                name = m.get("modelName")
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, m.get("creationTime"))
                rows.append(self.makeRow(name, "CustomModel", owner, lastUsed, {
                    "base_model": m.get("baseModelArn"),
                }))
        except Exception as e:
            self.logScanError("custom_models", e)
        return rows

    def _scanProvisionedThroughput(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanProvisionedThroughput.__name__)
        rows = []
        try:
            for p in self.client.list_provisioned_model_throughputs().get("provisionedModelSummaries", []):
                name = p.get("provisionedModelName")
                owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, p.get("lastModifiedTime"))
                rows.append(self.makeRow(name, "ProvisionedThroughput", owner, lastUsed, {
                    "status": p.get("status"), "model_arn": p.get("modelArn"),
                }))
        except Exception as e:
            self.logScanError("provisioned_throughput", e)
        return rows

    def _scanAgents(self, bedrockAgentClient):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanAgents.__name__)
        rows, agentIds = [], []
        try:
            for page in bedrockAgentClient.get_paginator("list_agents").paginate():
                for a in page.get("agentSummaries", []):
                    name = a.get("agentName")
                    agentId = a.get("agentId")
                    if agentId:
                        agentIds.append((agentId, name))
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, a.get("updatedAt"))
                    rows.append(self.makeRow(name, "Agent", owner, lastUsed, {
                        "agent_id": agentId, "status": a.get("agentStatus"),
                    }))
        except Exception as e:
            self.logScanError("list_agents", e)
        return rows, agentIds

    def _scanAgentAliases(self, bedrockAgentClient, agentIds):
        # No account-wide "list all aliases" call — aliases are listed
        # per agent, so this loops over every agent found above.
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanAgentAliases.__name__)
        rows = []
        for agentId, agentName in agentIds:
            try:
                for page in bedrockAgentClient.get_paginator("list_agent_aliases").paginate(agentId=agentId):
                    for alias in page.get("agentAliasSummaries", []):
                        aliasName = alias.get("agentAliasName")
                        resourceName = f"{agentName}/{aliasName}" if agentName else aliasName
                        owner, lastUsed = self.resolveOwnerAndLastUsed(resourceName, {}, alias.get("updatedAt"))
                        rows.append(self.makeRow(resourceName, "AgentAlias", owner, lastUsed, {
                            "agent_id": agentId,
                            "agent_alias_id": alias.get("agentAliasId"),
                            "status": alias.get("agentAliasStatus"),
                        }))
            except Exception as e:
                self.logScanError(f"list_agent_aliases:{agentId}", e)
        return rows

    def _scanKnowledgeBases(self, bedrockAgentClient):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanKnowledgeBases.__name__)
        rows = []
        try:
            for page in bedrockAgentClient.get_paginator("list_knowledge_bases").paginate():
                for kb in page.get("knowledgeBaseSummaries", []):
                    name = kb.get("name")
                    owner, lastUsed = self.resolveOwnerAndLastUsed(name, {}, kb.get("updatedAt"))
                    rows.append(self.makeRow(name, "KnowledgeBase", owner, lastUsed, {
                        "knowledge_base_id": kb.get("knowledgeBaseId"), "status": kb.get("status"),
                    }))
        except Exception as e:
            self.logScanError("list_knowledge_bases", e)
        return rows

    def _scanLoggingConfig(self):
        logUtils.logInfo(MODULE_NAME, "Inside " + self._scanLoggingConfig.__name__)
        rows = []
        try:
            cfg = self.client.get_model_invocation_logging_configuration().get("loggingConfig")
            enabled = bool(cfg)
            rows.append(self.makeRow(
                f"{self.region}-model-invocation-logging",
                "ModelInvocationLoggingConfiguration",
                "N/A (account-level config)",
                "N/A (config object, not a usage record)",
                {
                    "invocation_logging_enabled": enabled,
                    "s3_destination": (cfg or {}).get("s3Config"),
                    "cloudwatch_destination": (cfg or {}).get("cloudWatchConfig"),
                },
            ))
        except Exception as e:
            self.logScanError("logging_config_resource", e)
        return rows
