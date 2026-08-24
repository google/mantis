import json
import os
from typing import Annotated, Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from google import adk
from google.adk.workflow import Workflow, Edge, START, node, RetryConfig, DEFAULT_ROUTE
from google.adk.models.lite_llm import LiteLlm
from google.adk.agents.context import Context
from google.adk.skills import load_skill_from_dir
from google.adk.tools.skill_toolset import SkillToolset

from core.config import get_llm_kwargs, DEFAULT_MODEL
from core.environments import ENVIRONMENTS, get_shared_proxy_environment
from core.sandbox import SANDBOXES
from tools import TOOLS

DEFAULT_SEED_PROMPT = "Initial Task Input: Evaluate {filepath}"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentNode(_Base):
    id: str
    type: Literal["agent"]
    skill: Optional[str] = None
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    api_base: Optional[str] = None
    timeout: Optional[float] = Field(default=None, gt=0)
    reasoning_effort: Optional[str] = None
    tools: list[str] = Field(default_factory=list)
    on_enter_status: Optional[str] = None
    output_schema: Optional[str] = None   # class name in core.schemas
    output_key: Optional[str] = None      # session-state key to write it to

    @model_validator(mode="after")
    def validate_skill_or_prompt(self) -> "AgentNode":
        if not self.skill and not self.system_prompt:
            raise ValueError(f"Agent node '{self.id}' must specify either 'skill' or 'system_prompt'.")
        return self


class ClassifierNode(_Base):
    id: str
    type: Literal["classifier"]
    routes: list[str] = Field(min_length=1)
    max_visits: int = Field(default=1, ge=0)


NodeSpec = Annotated[AgentNode | ClassifierNode, Field(discriminator="type")]


class EdgeSpec(_Base):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    on: Optional[str | list[str]] = None


class SandboxConfig(_Base):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    type: str = "static-only"
    image: Optional[str] = None
    runtime: Optional[str] = None
    container_tool: Optional[str] = None
    timeout_seconds: Optional[int] = None
    options: dict[str, Any] = Field(default_factory=dict)


class GlobalConfig(_Base):
    db_path: str = "knowledge.db"
    default_model: str = DEFAULT_MODEL
    api_base: Optional[str] = None
    timeout: Optional[float] = Field(default=None, gt=0)
    reasoning_effort: Optional[str] = None
    retry_attempts: int = Field(default=3, ge=0)
    seed_prompt: str = DEFAULT_SEED_PROMPT
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    @field_validator("seed_prompt")
    @classmethod
    def validate_seed_prompt(cls, v: str) -> str:
        try:
            formatted = v.format(filepath="/path/to/test.py")
            if "/path/to/test.py" not in formatted:
                raise ValueError("must contain '{filepath}' placeholder")
        except Exception as e:
            raise ValueError(f"Global 'seed_prompt' is invalid: {e}")
        return v


class WorkflowSpec(_Base):
    name: str = "declarative_workflow"
    config: GlobalConfig = Field(default_factory=GlobalConfig)
    nodes: list[NodeSpec] = Field(default_factory=list)
    edges: list[EdgeSpec] = Field(default_factory=list)


def create_classifier(node_id: str, routes: list[str], max_visits: int = 1):
    async def _classify(ctx: Context, node_input: Any = None):
        state_key = f"{node_id}_visits"
        visits = ctx.state.get(state_key, 0) + 1

        verdict = None
        if isinstance(node_input, dict) and "route" in node_input:
            verdict = node_input
        elif hasattr(node_input, "route") and getattr(node_input, "route") is not None:
            verdict = node_input
        elif isinstance(node_input, str):
            try:
                parsed = json.loads(node_input)
                if isinstance(parsed, dict) and "route" in parsed:
                    verdict = parsed
                elif isinstance(parsed, str) and parsed in routes:
                    verdict = parsed
            except Exception:
                if node_input in routes:
                    verdict = node_input

        if verdict is None:
            verdict = ctx.state.get("verdict") or (node_input if isinstance(node_input, dict) else {})

        if isinstance(verdict, dict):
            route = verdict.get("route")
        elif hasattr(verdict, "route"):
            route = getattr(verdict, "route")
        elif isinstance(verdict, str):
            route = verdict
        else:
            route = None

        if isinstance(route, str):
            route = route.lower().strip()

        if max_visits and max_visits > 1 and visits >= max_visits:
            return adk.Event(output=node_input, state={state_key: visits}, route="exceeded")

        if route and route in routes:
            return adk.Event(output=node_input, state={state_key: visits}, route=route)

        if route:
            print(f"[{node_id}] verdict '{route}' not in declared routes {routes}; routing to fallback")

        return adk.Event(output=node_input, state={state_key: visits}, route=DEFAULT_ROUTE)

    return node(_classify, name=node_id)


def load_workflow_from_json(json_path: str) -> tuple[Workflow, dict]:
    if not os.path.exists(json_path):
        raise ValueError(f"Cannot find layout definition at {json_path}")
        
    with open(json_path, 'r', encoding='utf-8') as f:
        raw_json = json.load(f)

    if not isinstance(raw_json, dict):
        raise ValueError(f"Workflow layout JSON at {json_path} must be a dictionary.")

    spec = WorkflowSpec.model_validate(raw_json)

    errors = []
    base_dir = os.path.dirname(os.path.abspath(json_path))

    if spec.config.sandbox.type not in SANDBOXES and spec.config.sandbox.type not in ENVIRONMENTS:
        errors.append(
            f"Unknown sandbox type '{spec.config.sandbox.type}'. Available: {sorted(ENVIRONMENTS)}"
        )

    nodes = {}
    node_specs = {}
    declared_node_ids = set()

    for node_cfg in spec.nodes:
        node_id = node_cfg.id
        if not node_id.isidentifier():
            errors.append(f"Node id '{node_id}' is not a valid Python identifier.")
            continue
        if node_id == "START":
            errors.append("Node id 'START' is reserved for workflow entry.")
            continue
        if node_id in declared_node_ids:
            errors.append(f"Duplicate node id '{node_id}' found.")
            continue
        declared_node_ids.add(node_id)

        if isinstance(node_cfg, ClassifierNode):
            if len(node_cfg.routes) != len(set(node_cfg.routes)):
                errors.append(f"Classifier '{node_id}' routes contain duplicates: {node_cfg.routes}.")
            nodes[node_id] = create_classifier(node_id, node_cfg.routes, max_visits=node_cfg.max_visits)
            allowed_routes = set(node_cfg.routes) | {DEFAULT_ROUTE}
            if node_cfg.max_visits > 1:
                allowed_routes.add("exceeded")
            node_specs[node_id] = {"type": "classifier", "routes": allowed_routes}
            continue

        if isinstance(node_cfg, AgentNode):
            node_has_error = False
            try:
                _, llm_kwargs = get_llm_kwargs(
                    node_cfg.model,
                    spec.config.default_model,
                    api_base=node_cfg.api_base,
                    default_api_base=spec.config.api_base,
                    timeout=node_cfg.timeout,
                    default_timeout=spec.config.timeout,
                    reasoning_effort=node_cfg.reasoning_effort,
                    default_reasoning_effort=spec.config.reasoning_effort,
                )
            except Exception as e:
                errors.append(f"Node {node_id}: {str(e)}")
                node_has_error = True
                llm_kwargs = {}

            instruction = ""
            agent_tools = []
            tools_list = []
            for t in node_cfg.tools:
                if t in TOOLS:
                    tools_list.append(TOOLS[t])
                else:
                    errors.append(f"Node {node_id}: Unknown tool '{t}'")
                    node_has_error = True

            if node_cfg.skill:
                candidate_paths = [
                    os.path.normpath(os.path.join(base_dir, node_cfg.skill)),
                    os.path.normpath(os.path.join(base_dir, "..", node_cfg.skill)),
                    os.path.normpath(node_cfg.skill),
                ]
                resolved_skill_path = None
                for cp in candidate_paths:
                    if os.path.isdir(cp) and os.path.isfile(os.path.join(cp, "SKILL.md")):
                        resolved_skill_path = cp
                        break

                if resolved_skill_path:
                    try:
                        skill_obj = load_skill_from_dir(resolved_skill_path)
                        skill_ts = SkillToolset(
                            skills=[skill_obj],
                            environment=get_shared_proxy_environment(),
                        )
                        agent_tools = tools_list + [skill_ts]
                        instruction = (
                            f"You are the '{node_id}' stage in the Mantis vulnerability review pipeline.\n"
                            f"Execute your assigned skill '{skill_obj.frontmatter.name}' using your available tools.\n"
                            f"Retrieve upstream context using your specialized tools (e.g. get_findings, get_threat_model, get_plan, get_summary, read_file) and persist state via your write and record tools."
                        )
                    except Exception as se:
                        errors.append(f"Node {node_id}: Failed to load skill from '{resolved_skill_path}': {se}")
                        node_has_error = True
                else:
                    errors.append(f"Node {node_id}: Skill directory not found at any candidate location for '{node_cfg.skill}'")
                    node_has_error = True

            elif node_cfg.system_prompt:
                resolved_prompt = os.path.normpath(os.path.join(base_dir, node_cfg.system_prompt))
                if os.path.isfile(resolved_prompt):
                    with open(resolved_prompt, 'r', encoding='utf-8') as pf:
                        instruction = pf.read()
                    agent_tools = tools_list
                else:
                    errors.append(f"Node {node_id}: System prompt not found or is a directory at '{resolved_prompt}'")
                    node_has_error = True

            schema_cls = None
            if node_cfg.output_schema:
                import core.schemas
                schema_cls = getattr(core.schemas, node_cfg.output_schema, None)
                if schema_cls is None:
                    errors.append(f"Node {node_id}: unknown output_schema '{node_cfg.output_schema}'")
                    node_has_error = True

            if node_has_error:
                continue

            agent = adk.Agent(
                name=node_id,
                model=LiteLlm(**llm_kwargs),
                instruction=instruction,
                tools=agent_tools,
                output_schema=schema_cls,
                output_key=node_cfg.output_key,
            )
            node_retry = RetryConfig(max_attempts=spec.config.retry_attempts) if spec.config.retry_attempts > 1 else None
            nodes[node_id] = node(agent, name=node_id, retry_config=node_retry)
            node_specs[node_id] = {"type": "agent"}

    # Wire Edges
    edge_map = {}
    edge_nodes_referenced = set()
    node_out_routes = {nid: set() for nid in nodes}

    for edge_cfg in spec.edges:
        from_str = edge_cfg.from_node
        to_str = edge_cfg.to_node
        route = edge_cfg.on

        if from_str == "START":
            from_node = START
            if route is not None:
                errors.append(f"Edge from START to '{to_str}' must not have a route condition ('on': '{route}').")
        else:
            if from_str not in declared_node_ids:
                errors.append(f"Edge references unknown from_node: '{from_str}'")
                continue
            from_node = nodes.get(from_str)
            if from_node is None:
                continue
            edge_nodes_referenced.add(from_str)

        if to_str not in declared_node_ids:
            errors.append(f"Edge references unknown to_node: '{to_str}'")
            continue
        to_node = nodes.get(to_str)
        if to_node is None:
            continue
        edge_nodes_referenced.add(to_str)

        # Validate route consistency
        if from_str in node_specs:
            nspec = node_specs[from_str]
            if nspec["type"] == "classifier":
                declared_routes = nspec["routes"]
                if route is None:
                    errors.append(
                        f"Edge from classifier '{from_str}' to '{to_str}' is missing route condition ('on')."
                    )
                elif isinstance(route, list):
                    for r in route:
                        if r not in declared_routes:
                            errors.append(
                                f"Edge from classifier '{from_str}' references undeclared route '{r}'."
                            )
                        else:
                            node_out_routes[from_str].add(r)
                elif route not in declared_routes:
                    errors.append(
                        f"Edge from classifier '{from_str}' references undeclared route '{route}'."
                    )
                else:
                    node_out_routes[from_str].add(route)
            elif nspec["type"] == "agent":
                if route is not None:
                    errors.append(
                        f"Edge from agent '{from_str}' to '{to_str}' must not specify a route condition ('on': '{route}'). Agents do not emit routes."
                    )

        key = (from_str, to_str)
        if key in edge_map:
            errors.append(f"Duplicate edge from '{from_str}' to '{to_str}'. Use a list in 'on' to specify multiple routes.")
        else:
            edge_map[key] = {"from_node": from_node, "to_node": to_node, "route": route}

    # Validate that all declared classifier routes have outgoing edges
    for node_id, nspec in node_specs.items():
        if nspec["type"] == "classifier":
            orig_node = next((n for n in spec.nodes if n.id == node_id), None)
            if orig_node and isinstance(orig_node, ClassifierNode):
                declared = set(orig_node.routes)
                used = node_out_routes.get(node_id, set())
                missing = declared - used
                if missing:
                    errors.append(
                        f"Node '{node_id}' declared route(s) {sorted(missing)} with no outgoing edge."
                    )

    # Orphan node validation
    for node_id in nodes:
        if node_id not in edge_nodes_referenced:
            errors.append(f"Node '{node_id}' is defined in 'nodes' but is not connected by any edge.")

    # Terminal sink validation
    if nodes:
        terminal_nodes = set(nodes.keys()) - {f for (f, _) in edge_map if f != "START"}
        if len(terminal_nodes) == 0:
            errors.append(
                "Workflow must have at least one terminal sink node, but found none (cycle without sink)."
            )

    if errors:
        raise ValueError("Graph validation failed:\n" + "\n".join(errors))

    edges = [
        Edge(from_node=item["from_node"], to_node=item["to_node"], route=item["route"])
        if item["route"] is not None
        else Edge(from_node=item["from_node"], to_node=item["to_node"])
        for item in edge_map.values()
    ]

    node_status_map = {
        node_cfg.id: node_cfg.on_enter_status
        for node_cfg in spec.nodes
        if isinstance(node_cfg, AgentNode) and node_cfg.on_enter_status is not None
    }
    cfg = spec.config.model_dump()
    cfg["on_enter_status"] = node_status_map

    return (
        Workflow(
            name=spec.name,
            edges=edges
        ),
        cfg
    )

