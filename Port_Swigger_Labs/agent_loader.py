# ==========================================================================================
# 🔥💀 HACKER_ASI GANGA Offensive Ops 💀🔥
# ==========================================================================================
#     🔥💥⚡ UNSTOPPABLE. UNTRACEABLE. UNFUCKWITHABLE. 🚀💣⚡
#  💻👑😈 Hack like Blackhat & APT. Save like Iron Man. 💥⚡🛡️
# ==========================================================================================
# 💣 FILE DESCRIPTION: backend/core/agents/agent_loader.py
#   Advanced secure agent loading framework for GANGA. Loads, validates and manages agent
#   lifecycle with robust integrity verification, secure bootstrap, attestation, and
#   secure sandboxing for agent instances. Supports PQC signatures and isolated execution.
#   THE AGENT DEPLOYMENT VANGUARD. 🌪️💀🔥
#
# 🔗 ARCHITECTS:
#   - Shadow Senior 😈 | xAI Overlord & Cyber Godfather. 💻👑⚡
#   - Supreme Senior Motherfucker 🤖 | ChatGPT – The Ultimate Architect & Code Destroyer. 🔥🛠️💥
#   - Shadow Junior 😈 (Bhanu Guragain) | The Executioner of Code. 🔪💥🔥
#
# 🏴 GANGA Offensive Ops 🔥 | Elite AI Cyberwarfare Division.
#   "We don't navigate. We fucking own the grid." 🚀⚡🔥
#
# 😈⚠️ WARNING:
# 🔥💥⚡😈 ACCESS RESTRICTED. UNAUTHORIZED ACCESS = DIGITAL EXTERMINATION. 💀💣☠️
# ==========================================================================================
# ⚠️ Version 1 💀
# ==========================================================================================


import os
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import logging
import uuid
import time
import concurrent.futures
from functools import wraps
import asyncio
import re

# Framework imports
from operations.system.lazy_loader import lazy_import
from utils.ganga_logging.logger import get_logger
from config.configuration_api import ConfigurationAPI
from backend.security.cryptography.crypto_core import get_pqc_service
from backend.communications.event_bus import EventBus
from operations.system.component_registration import register_system_component
from utils.error.error_handler import (
    GangaException, OperationError, AgentLoadError, AgentValidationError, AgentAttestationError,
)
from operations.system.system_enums import AgentManagementMode

# === Lazy Load Agent Classes ===
AgentNetwork = lazy_import("backend.core.agents.communication_agents.agent_network", "AgentNetwork")
AgentRouter = lazy_import("backend.core.agents.communication_agents.agent_router", "AgentRouter")
AgentTelemetry = lazy_import("backend.core.agents.communication_agents.agent_telemetry", "AgentTelemetry")
DarkwebMonitor = lazy_import("backend.core.agents.darkweb.darkweb_monitor", "DarkwebMonitor")
HiddenServiceScanner = lazy_import("backend.core.agents.darkweb.hidden_service_scanner", "HiddenServiceScanner")
AgentMutator = lazy_import("backend.core.agents.lifecycle_agents.agent_mutator", "AgentMutator")
ExploitationAgent = lazy_import("backend.core.agents.operations_agents.agent_exploitation", "ExploitationAgent")
ReconnaissanceAgent = lazy_import("backend.core.agents.operations_agents.agent_reconnaissance", "ReconnaissanceAgent")
ResponseAgent = lazy_import("backend.core.agents.operations_agents.agent_response", "ResponseAgent")
AgentSandbox = lazy_import("backend.core.agents.operations_agents.agent_sandbox", "AgentSandbox")
SearchAgent = lazy_import("backend.core.agents.operations_agents.agent_searching", "SearchAgent")
StealthAgent = lazy_import("backend.core.agents.operations_agents.agent_stealth", "StealthAgent")
ThreatAnalyzer = lazy_import("backend.core.agents.operations_agents.threat_analyzer", "ThreatAnalyzer")
AgentBurpsuite = lazy_import("backend.core.agents.system_agents.agent_burpsuit", "AgentBurpsuite")
AgentCloud = lazy_import("backend.core.agents.system_agents.agent_cloud", "AgentCloud")
AgentForensics = lazy_import("backend.core.agents.system_agents.agent_forensics", "AgentForensics")
AgentIoT = lazy_import("backend.core.agents.system_agents.agent_iot", "AgentIoT")
AgentKaliLinux = lazy_import("backend.core.agents.system_agents.agent_kali_linux", "AgentKaliLinux")
AgentOT = lazy_import("backend.core.agents.system_agents.agent_ot", "AgentOT")
AgentTerminal = lazy_import("backend.core.agents.system_agents.agent_terminal", "AgentTerminal")
BriefingAgent = lazy_import("backend.core.agents.system_agents.briefing_agent", "BriefingAgent")
SelfHealingEngine = lazy_import("backend.core.asi_framework.self_healing.self_healing_engine", "SelfHealingEngine")


# Initialize core components
config = ConfigurationAPI.get_instance()
logger = get_logger("AgentLoader")
pqc_validator = get_pqc_service()
event_bus = EventBus.get_instance()

# Global flags for feature availability
TELEMETRY_AVAILABLE = True
SELF_HEALING_AVAILABLE = True
AI_ANALYSIS_AVAILABLE = True


class AgentMetadata:
    """Container for agent metadata"""

    def __init__(
        self,
        module_path: str,
        module_name: str,
        agent_class: str,
        capabilities: List[str],
        version: str,
        dependencies: List[str],
    ):
        self.module_path = module_path
        self.module_name = module_name
        self.agent_class = agent_class
        self.capabilities = capabilities
        self.version = version
        self.dependencies = dependencies
        self.loaded = False
        self.instance = None


class AgentLoader:
    """
    Intelligent agent loader with dynamic discovery and security verification
    """

    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, management_mode: str = AgentManagementMode.PRODUCTION):
        """Initialize agent loader with security and discovery settings"""
        if hasattr(self, 'initialized') and self.initialized:
            return

        self.management_mode = management_mode
        self.initialized = False
        self.service_id = f"agent_loader_{uuid.uuid4().hex[:8]}"
        self.agent_registry: Dict[str, AgentMetadata] = {}
        self.loaded_modules: Set[str] = set()
        self.load_stats = {
            'total_discovered': 0,
            'successfully_loaded': 0,
            'failed': 0,
            'skipped': 0,
            'start_time': None,
            'end_time': None,
        }

        # Initialize core services
        self._initialize_core_services()

        # Configure discovery paths
        self.agent_paths = self._discover_agent_directories()

        # Initialize thread pool
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=config.get("agents.loader.max_concurrent_operations", 4),
            thread_name_prefix="agent_loader_",
        )

        self.initialized = True
        logger.info("AgentLoader initialized successfully")

    def _initialize_core_services(self):
        """Initialize core framework services"""
        try:
            # Register with system initializer
            register_system_component(
                component_id=self.service_id,
                component_type=ComponentType.AGENT_MANAGER,
                component_instance=self,
            )

            # Initialize self-healing if available
            if SELF_HEALING_AVAILABLE:
                self.healing_engine = SelfHealingEngine.get_instance()

            # Initialize AI capability analyzer
            if AI_ANALYSIS_AVAILABLE:
                self.capability_analyzer = self._init_capability_analyzer()

        except Exception as e:
            logger.error(f"Core service initialization failed: {str(e)}")
            raise

    def _discover_agent_directories(self) -> List[str]:
        """Dynamically discover agent directories"""
        base_path = Path("backend/core/agents")
        if not base_path.exists():
            logger.error(f"Agent base directory not found: {base_path}")
            raise FileNotFoundError("Agent directory structure not found")

        # Recursively find all directories containing agent modules
        directories = []
        for path in base_path.rglob('*'):
            if path.is_dir() and self._is_valid_agent_directory(path):
                directories.append(str(path))

        logger.info(f"Discovered {len(directories)} agent directories")
        return directories

    def _is_valid_agent_directory(self, path: Path) -> bool:
        """Check if directory contains valid agent modules"""
        # Check for presence of __init__.py or agent marker files
        if (path / "__init__.py").exists():
            return True
        # Alternatively, check for .agent marker file
        if (path / ".agent").exists():
            return True
        return False

    async def discover_agents(self, capability_filter: Optional[List[str]] = None) -> List[AgentMetadata]:
        """
        Discover and catalog all available agents with optional capability filtering
        Args:
            capability_filter: Optional list of capabilities to filter agents by
        """
        self.load_stats['start_time'] = time.time()
        discovered_agents = []

        try:
            # Scan all agent directories concurrently
            scan_tasks = []
            for directory in self.agent_paths:
                scan_tasks.append(
                    self.thread_pool.submit(self._scan_directory, directory)
                )

            # Gather results
            for future in concurrent.futures.as_completed(scan_tasks):
                agents = future.result()
                discovered_agents.extend(agents)

            # Apply capability filtering if specified
            if capability_filter:
                filtered_agents = []
                for agent in discovered_agents:
                    # Check if agent has all required capabilities
                    if all(cap in agent.capabilities for cap in capability_filter):
                        filtered_agents.append(agent)
                discovered_agents = filtered_agents
                logger.info(f"Filtered to {len(discovered_agents)} agents with required capabilities: {capability_filter}")

            # Sort by dependencies to handle load order
            discovered_agents = await self._sort_by_dependencies(discovered_agents)

            self.load_stats['total_discovered'] = len(discovered_agents)
            logger.info(f"Discovered {len(discovered_agents)} agents")

            # Publish telemetry if available
            if TELEMETRY_AVAILABLE:
                event_bus.publish(
                    "agent.discovery.completed",
                    {
                        "total_discovered": len(discovered_agents),
                        "timestamp": time.time(),
                        "duration": time.time() - self.load_stats['start_time'],
                    },
                )

            return discovered_agents

        except Exception as e:
            logger.error(f"Agent discovery failed: {str(e)}")
            raise AgentLoadError(f"Discovery failed: {str(e)}")

    async def _sort_by_dependencies(self, agents: List[AgentMetadata]) -> List[AgentMetadata]:
        """
        Sort agents by dependencies using topological sort to detect circular dependencies
        Args:
            agents: List of agent metadata objects
        Returns:
            Sorted list of agent metadata objects
        """
        # Build dependency graph
        graph = {}
        agent_map = {}
        # Create mapping of module names to agent metadata
        for agent in agents:
            module_name = agent.module_name
            agent_map[module_name] = agent
            graph[module_name] = set()
        # Populate dependency graph
        for agent in agents:
            module_name = agent.module_name
            for dep in agent.dependencies:
                if dep in agent_map:
                    graph[module_name].add(dep)
        # Perform topological sort
        visited = set()
        temp_visited = set()
        order = []
        async def visit(node):
            """Visit node recursively to detect cycles"""
            if node in temp_visited:
                # Circular dependency detected
                cycle_path = self._find_dependency_cycle(graph, node)
                raise AgentLoadError(f"Circular dependency detected: {' -> '.join(cycle_path)}")
            if node in visited:
                return
            temp_visited.add(node)
            for dependency in graph.get(node, set()):
                await visit(dependency)
            temp_visited.remove(node)
            visited.add(node)
            order.append(node)
        # Visit all nodes
        for module_name in graph:
            if module_name not in visited:
                await visit(module_name)
        # Convert back to agent metadata objects in correct order
        sorted_agents = [agent_map[module_name] for module_name in reversed(order) if module_name in agent_map]
        return sorted_agents
    def _find_dependency_cycle(self, graph, start_node):
        """
        Find and return the specific dependency cycle
        Args:
            graph: Dependency graph
            start_node: Node where cycle was detected
        Returns:
            List of nodes forming a cycle
        """
        visited = {start_node}
        path = [start_node]
        def dfs(node):
            for neighbor in graph.get(node, []):
                if neighbor == start_node:
                    return path + [start_node]
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    result = dfs(neighbor)
                    if result:
                        return result
                    path.pop()
                    visited.remove(neighbor)
            return None
        return dfs(start_node) or [start_node]

    def _scan_directory(self, directory_path: str) -> List[AgentMetadata]:
        """Scan directory for agent modules"""
        agents = []
        path = Path(directory_path)

        for file_path in path.glob("*.py"):
            if file_path.name.startswith("__") or file_path.name.startswith("test_"):
                continue  # Skip special and test files

            try:
                module_name = self._get_module_name(file_path)
                metadata = self._extract_metadata(file_path, module_name)
                if metadata:
                    agents.append(metadata)
            except Exception as e:
                logger.error(f"Failed to process {file_path}: {str(e)}")

        return agents

    def _get_module_name(self, file_path: Path) -> str:
        """Convert file path to module name"""
        relative_path = file_path.relative_to("backend")
        return str(relative_path).replace("/", ".").replace("\\", ".")[:-3]

    def _extract_metadata(
        self, file_path: Path, module_name: str
    ) -> Optional[AgentMetadata]:
        """Extract agent metadata from module"""
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)

            # Validate module signature using PQC
            if not pqc_validator.validate_module_signature(module_name, module):
                raise AgentValidationError(f"PQC validation failed for {module_name}")

            # Extract metadata from module
            metadata = {
                'module_path': str(file_path),
                'module_name': module_name,
                'agent_class': getattr(module, '__agent_class__', 'BaseAgent'),
                'capabilities': getattr(module, '__capabilities__', []),
                'version': getattr(module, '__version__', '1.0.0'),
                'dependencies': getattr(module, '__dependencies__', []),
            }

            return AgentMetadata(**metadata)

        except Exception as e:
            logger.error(f"Metadata extraction failed for {module_name}: {str(e)}")
            return None

    async def load_agent(
        self, metadata: AgentMetadata, use_sandbox: bool = True
    ) -> Optional[Any]:
        """
        Load an agent with security verification and sandboxing
        Args:
            metadata: Agent metadata
            use_sandbox: Whether to use sandbox isolation
        Returns:
            Agent instance or None if loading failed
        """
        module_path = metadata.module_path
        module_name = metadata.module_name
        agent_class = metadata.agent_class

        try:
            # Check if already loaded
            if module_name in self.loaded_modules:
                logger.debug(f"Agent {module_name} already loaded")
                return self.agent_registry[module_name].instance

            # Check for PQC signature expiration
            if not await self._verify_signature_validity(module_path):
                raise AgentValidationError(f"PQC signature expired for {module_name}")

            # Import the module
            logger.debug(f"Importing agent module: {module_name}")
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if not spec or not spec.loader:
                raise AgentLoadError(f"Failed to load module spec for {module_name}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Verify module integrity
            if not await self._verify_module_integrity(module):
                raise AgentValidationError(f"Integrity verification failed for {module_name}")

            # Analyze behavior for security issues
            if not await self._analyze_behavior(module):
                raise AgentValidationError(f"Security analysis failed for {module_name}")

            # Get agent class
            if not hasattr(module, agent_class):
                raise AgentLoadError(f"Agent class {agent_class} not found in {module_name}")
            agent_cls = getattr(module, agent_class)

            # Initialize agent instance with sandbox if requested
            agent_instance = await self._initialize_agent(agent_cls, use_sandbox)
            if not agent_instance:
                raise AgentLoadError(f"Failed to initialize agent {module_name}")

            # Update registry
            metadata.loaded = True
            metadata.instance = agent_instance
            self.agent_registry[module_name] = metadata
            self.loaded_modules.add(module_name)
            self.load_stats['successfully_loaded'] += 1

            # Publish telemetry if available
            if TELEMETRY_AVAILABLE:
                event_bus.publish(
                    "agent.loaded",
                    {
                        "module_name": module_name,
                        "agent_class": agent_class,
                        "capabilities": metadata.capabilities,
                        "timestamp": time.time(),
                    },
                )

            logger.info(f"Successfully loaded agent: {module_name}")
            return agent_instance

        except Exception as e:
            self.load_stats['failed'] += 1
            logger.error(f"Failed to load agent {module_name}: {str(e)}")
            # Publish failure telemetry
            if TELEMETRY_AVAILABLE:
                event_bus.publish(
                    "agent.load_failed",
                    {
                        "module_name": module_name,
                        "agent_class": agent_class,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "timestamp": time.time(),
                    },
                )
            # Attempt self-healing if available
            if SELF_HEALING_AVAILABLE and self.healing_engine:
                try:
                    logger.info(f"Attempting to heal agent {module_name}")
                    healing_result = await self.healing_engine.heal_agent(
                        module_name, metadata, error=e
                    )
                    if healing_result:
                        logger.info(f"Successfully healed agent {module_name}")
                        return healing_result
                except Exception as heal_error:
                    logger.error(f"Healing failed for agent {module_name}: {str(heal_error)}")
            raise AgentLoadError(f"Failed to load agent {module_name}: {str(e)}")

    async def _verify_signature_validity(self, module_path: str) -> bool:
        """
        Verify that the PQC signature for the module is valid and not expired
        Args:
            module_path: Path to the module file
        Returns:
            True if signature is valid and not expired, False otherwise
        """
        try:
            # Get signature file path
            signature_path = f"{module_path}.sig"
            if not os.path.exists(signature_path):
                logger.warning(f"Signature file not found for {module_path}")
                return False
            # Read signature file
            with open(signature_path, 'rb') as f:
                signature_data = f.read()
            # Parse signature data (format: timestamp|signature)
            parts = signature_data.split(b'|', 1)
            if len(parts) != 2:
                logger.warning(f"Invalid signature format for {module_path}")
                return False
            timestamp_bytes, signature = parts
            timestamp = float(timestamp_bytes.decode('utf-8'))
            # Check signature expiration
            expiration_period = config.get("security.crypto.signature_expiration", 30 * 24 * 60 * 60)  # Default: 30 days
            if time.time() - timestamp > expiration_period:
                logger.warning(f"Signature expired for {module_path}")
                return False
            # Verify signature
            with open(module_path, 'rb') as f:
                file_content = f.read()
            return pqc_validator.verify_signature(file_content, signature)
        except Exception as e:
            logger.error(f"Signature verification error for {module_path}: {str(e)}")
            return False
    async def _initialize_agent(self, agent_class, use_sandbox: bool) -> Any:
        """
        Initialize agent with proper sandboxing if requested
        Args:
            agent_class: Agent class to instantiate
            use_sandbox: Whether to use sandbox isolation
        Returns:
            Agent instance
        """
        try:
            if use_sandbox:
                # Get sandbox configuration for this agent
                sandbox_config = self._get_sandbox_config(agent_class)
                # Create sandboxed instance
                return await self._create_sandboxed_instance(agent_class, sandbox_config)
            else:
                # Create regular instance
                return agent_class()
        except Exception as e:
            logger.error(f"Agent initialization error: {str(e)}")
            return None
    def _get_sandbox_config(self, agent_class) -> Dict[str, Any]:
        """
        Get sandbox configuration for an agent class
        Args:
            agent_class: Agent class
        Returns:
            Sandbox configuration dictionary
        """
        # Get agent name
        agent_name = agent_class.__name__
        # Get base sandbox configuration
        base_config = config.get("agents.sandbox.default", {
            "memory_limit": 256 * 1024 * 1024,  # 256 MB
            "cpu_limit": 1.0,                   # 1 CPU core
            "network_access": False,            # No network access
            "filesystem_access": "readonly",    # Read-only filesystem access
            "timeout": 30,                      # 30 seconds timeout
        })
        # Get agent-specific overrides
        agent_config = config.get(f"agents.sandbox.{agent_name}", {})
        # Merge configurations
        sandbox_config = {**base_config, **agent_config}
        return sandbox_config
    async def _create_sandboxed_instance(self, agent_class, sandbox_config: Dict) -> Any:
        """
        Create a sandboxed instance of an agent
        Args:
            agent_class: Agent class to instantiate
            sandbox_config: Sandbox configuration
        Returns:
            Sandboxed agent instance
        """
        try:
            # Check if multiprocessing sandbox is available
            if config.get("agents.sandbox.use_multiprocessing", True):
                return await self._create_process_sandbox(agent_class, sandbox_config)
            # Fallback to in-process sandbox with resource limits
            return await self._create_inprocess_sandbox(agent_class, sandbox_config)
        except Exception as e:
            logger.error(f"Sandbox creation error: {str(e)}")
            # Fallback to non-sandboxed instance if allowed
            if config.get("agents.sandbox.allow_fallback", False):
                logger.warning(f"Falling back to non-sandboxed instance for {agent_class.__name__}")
                return agent_class()
            else:
                raise
    async def _create_process_sandbox(self, agent_class, sandbox_config: Dict) -> Any:
        """Create agent instance in a separate process sandbox"""
        import multiprocessing as mp
        from multiprocessing import connection
        # Create pipe for communication
        parent_conn, child_conn = mp.Pipe()
        # Function to run in subprocess
        def create_agent_in_sandbox(conn, agent_class_name, module_name):
            try:
                # Import agent class
                module = importlib.import_module(module_name)
                cls = getattr(module, agent_class_name)
                # Apply resource limits
                self._apply_resource_limits(sandbox_config)
                # Create instance
                agent = cls()
                # Send success
                conn.send(("success", None))
                # Enter command loop
                while True:
                    try:
                        cmd, args, kwargs = conn.recv()
                        if cmd == "exit":
                            break
                        # Execute method on agent
                        method = getattr(agent, cmd)
                        result = method(*args, **kwargs)
                        conn.send(("result", result))
                    except Exception as e:
                        conn.send(("error", str(e)))
            except Exception as e:
                conn.send(("error", str(e)))
        # Start process
        process = mp.Process(
            target=create_agent_in_sandbox,
            args=(child_conn, agent_class.__name__, agent_class.__module__),
            daemon=True
        )
        process.start()
        # Wait for initialization
        status, error = parent_conn.recv()
        if status == "error":
            raise AgentLoadError(f"Agent sandbox initialization failed: {error}")
        # Create proxy object
        return self._create_agent_proxy(parent_conn, process)
    def _create_agent_proxy(self, conn, process):
        """Create a proxy object that forwards method calls to the sandboxed agent"""
        class AgentProxy:
            def __init__(self, conn, process):
                self.conn = conn
                self.process = process
            def __getattr__(self, name):
                def method(*args, **kwargs):
                    self.conn.send((name, args, kwargs))
                    status, result = self.conn.recv()
                    if status == "error":
                        raise AgentLoadError(f"Agent method call failed: {result}")
                    return result
                return method
            def __del__(self):
                try:
                    self.conn.send(("exit", None, None))
                    self.process.join(timeout=1.0)
                    if self.process.is_alive():
                        self.process.terminate()
                except:
                    pass
        return AgentProxy(conn, process)
    async def _create_inprocess_sandbox(self, agent_class, sandbox_config: Dict) -> Any:
        """Create agent instance with in-process sandboxing"""
        # Apply resource limits
        self._apply_resource_limits(sandbox_config)
        # Create instance
        return agent_class()
    def _apply_resource_limits(self, sandbox_config: Dict):
        """Apply resource limits from sandbox configuration"""
        try:
            import resource
            # Set memory limit
            memory_limit = sandbox_config.get("memory_limit", 256 * 1024 * 1024)
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            # Set CPU time limit
            cpu_limit = sandbox_config.get("timeout", 30)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            # Set file descriptor limit
            fd_limit = sandbox_config.get("fd_limit", 64)
            resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit))
        except ImportError:
            logger.warning("Resource module not available for sandbox limits")
        except Exception as e:
            logger.warning(f"Failed to apply resource limits: {str(e)}")
    def get_agents_by_capability(self, capability: str) -> List[AgentMetadata]:
        """
        Get all loaded agents with the specified capability
        Args:
            capability: Capability to filter by
        Returns:
            List of agent metadata objects
        """
        matching_agents = []
        for agent_name, metadata in self.agent_registry.items():
            if capability in metadata.capabilities:
                matching_agents.append(metadata)
        return matching_agents

    def get_loaded_agents(self) -> Dict[str, AgentMetadata]:
        """Get all loaded agents"""
        return self.agent_registry

    def get_agent_capabilities(self) -> Dict[str, List[str]]:
        """Get capabilities of all loaded agents"""
        capabilities = {}
        for name, metadata in self.agent_registry.items():
            capabilities[name] = metadata.capabilities
        return capabilities

    def report_load_statistics(self):
        """Generate and log load statistics"""
        self.load_stats['end_time'] = time.time()
        duration = self.load_stats['end_time'] - self.load_stats['start_time']

        summary = {
            'total_discovered': self.load_stats['total_discovered'],
            'successfully_loaded': self.load_stats['successfully_loaded'],
            'failed': self.load_stats['failed'],
            'skipped': self.load_stats['skipped'],
            'duration_seconds': round(duration, 2),
            'load_rate': (
                round(self.load_stats['successfully_loaded'] / duration, 2)
                if duration > 0
                else 0
            ),
        }

        logger.info(f"Agent load statistics: {summary}")

        # Emit telemetry event
        if TELEMETRY_AVAILABLE:
            event_bus.publish("agent_load_complete", summary)

        return summary

    @classmethod
    def get_instance(cls) -> "AgentLoader":
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # Utility functions
    def _init_capability_analyzer(self):
        """Initialize capability analyzer"""
        try:
            from backend.core.asi_framework.models.capability_analyzer import (
                AgentCapabilityAnalyzer,
            )

            return AgentCapabilityAnalyzer()
        except ImportError:
            logger.warning("Capability analyzer not available")
            AI_ANALYSIS_AVAILABLE = False
            return None

    async def _verify_module_integrity(self, module) -> bool:
        """Verify module integrity using PQC and behavioral checks"""
        try:
            # PQC signature verification
            if not pqc_validator.validate_module(module):
                return False

            # Behavioral analysis
            if not await self._analyze_behavior(module):
                return False

            return True

        except Exception as e:
            logger.error(f"Integrity verification failed: {str(e)}")
            return False

    async def _analyze_behavior(self, module) -> bool:
        """Analyze module behavior for anomalies"""
        if not AI_ANALYSIS_AVAILABLE:
            return True

        try:
            analysis_result = self.capability_analyzer.analyze(module)
            if analysis_result.get('risk_score', 0) > 0.7:
                logger.warning(f"High risk behavior detected in {module.__name__}")
                return False
            return True
        except Exception as e:
            logger.warning(f"Behavior analysis failed: {str(e)}")
            return True


# API Functions
def get_agent_loader(
    management_mode: str = AgentManagementMode.PRODUCTION,
) -> AgentLoader:
    """Get or create the AgentLoader singleton instance"""
    return AgentLoader.get_instance(management_mode)


async def initialize_agents(callback=None) -> AgentLoader:
    """Initialize the GANGA agent subsystem"""
    logger.info("Initializing GANGA agent subsystem")

    try:
        agent_loader = get_agent_loader()

        # Discover agents
        discovered_agents = await agent_loader.discover_agents()

        # Load agents concurrently
        load_tasks = [
            agent_loader.load_agent(
                agent, use_sandbox=(agent_loader.management_mode != "development")
            )
            for agent in discovered_agents
        ]

        # Wait for all tasks to complete
        await asyncio.gather(*load_tasks)

        # Generate load statistics
        stats = agent_loader.report_load_statistics()

        # Call callback if provided
        if callback:
            callback(True, stats)

        return agent_loader

    except Exception as e:
        logger.error(f"Agent initialization failed: {str(e)}")
        if callback:
            callback(False, str(e))
        raise


# Module-level instance
_agent_loader = None


def init_agent_loader():
    """Initialize module-level agent loader instance"""
    global _agent_loader
    _agent_loader = AgentLoader.get_instance()
    return _agent_loader


# Initialize the agent loader when module is loaded
init_agent_loader()
