"""Cedar schema for agent authorization (ADR-0022 §2)."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

NAMESPACE: Final = "Atf"

CEDAR_SCHEMA: Final = """
namespace Atf {
  entity Team;
  entity Agent in [Team] = { "tier": String };
  entity McpServer = { "delegation": String };
  entity Model;
  action "invoke_tool" appliesTo {
    principal: [Agent],
    resource: [McpServer],
    context: { "user": String, "user_scopes": Set<String>, "scopes": Set<String> }
  };
  action "call_model" appliesTo { principal: [Agent], resource: [Model], context: {} };
  action "delegate" appliesTo {
    principal: [Agent],
    resource: [Agent],
    context: { "user": String, "user_scopes": Set<String> }
  };
}
"""


class Action(StrEnum):
    INVOKE_TOOL = "invoke_tool"
    CALL_MODEL = "call_model"
    DELEGATE = "delegate"


class ResourceType(StrEnum):
    MCP_SERVER = "McpServer"
    MODEL = "Model"
    AGENT = "Agent"
