"""Source code leak detector analyzer for identifying exposed configuration files.

This analyzer probes for commonly exposed source code files and configuration
that leak information about the technology stack being used.
"""
from typing import List
import logging
from core.context import ScanContext
from models.detection import Detection, Evidence
from models.technology import Technology
from core.analyzer_registry import AnalyzerRegistry, filter_by_rule_types
from core.endpoints_loader import load_config
from fetch.http_client import fetch_url
import os

logger = logging.getLogger(__name__)


@AnalyzerRegistry.register(
    "source_code_leak",
    lambda rules: filter_by_rule_types(rules, {"git_config", "env_file", "package_manifest", "config_file"}),
    analyzer_type="active"
)
class SourceCodeLeakAnalyzer:
    """Active analyzer that probes for exposed source code and configuration files."""
    
    def __init__(self, rules: List[Technology]):
        self.rules = rules

    async def analyze(self, context: ScanContext) -> List[Detection]:
        """
        Probe for exposed source code files and configuration.
        
        This is an ACTIVE analyzer - it makes additional HTTP requests.
        """
        detections: List[Detection] = []
        base_url = context.url.rstrip('/')
        
        # Load leak paths from configuration
        leak_paths = self._load_leak_paths()
        
        # Probe for exposed files
        for path in leak_paths:
            endpoint = f"{base_url}{path}"
            
            try:
                response = await fetch_url(endpoint, timeout=5)
                
                # Check if file exists (200, 206, 304 are success codes)
                if response.status_code in [200, 206, 304]:
                    logger.warning(f"POTENTIAL SOURCE CODE LEAK: {endpoint} (status: {response.status_code})")
                    
                    # Analyze the leaked file content
                    detections.extend(
                        await self._analyze_leaked_content(
                            endpoint, 
                            response.text, 
                            path
                        )
                    )
            
            except Exception as e:
                logger.debug(f"Source code leak probe failed for {endpoint}: {e}")
                continue
        
        return detections

    async def _analyze_leaked_content(self, endpoint: str, content: str, path: str) -> List[Detection]:
        """
        Analyze leaked file content for technology hints.
        
        Args:
            endpoint: Full URL of leaked file
            content: File content
            path: File path
            
        Returns:
            List of detections from leaked content
        """
        detections: List[Detection] = []
        
        # Determine file type
        file_type = self._get_file_type(path)
        
        # Analyze based on file type
        if file_type == "git_config":
            detections.extend(self._analyze_git_config(endpoint, content))
        elif file_type == "env_file":
            detections.extend(self._analyze_env_file(endpoint, content))
        elif file_type == "package_manifest":
            detections.extend(self._analyze_package_manifest(endpoint, content))
        elif file_type == "config_file":
            detections.extend(self._analyze_config_file(endpoint, content))
        
        return detections

    def _analyze_git_config(self, endpoint: str, content: str) -> List[Detection]:
        """Analyze .git/config for technology hints."""
        detections: List[Detection] = []
        
        # Git config reveals repository info, remote URLs might show tech stack
        if content.lower():
            detections.append(
                Detection(
                    name="Git Repository",
                    category="Version Control",
                    confidence=1.0,
                    evidence=Evidence(
                        type="git_config",
                        value=endpoint,
                        name="Exposed .git/config"
                    ),
                    version=None
                )
            )
        
        return detections

    def _analyze_env_file(self, endpoint: str, content: str) -> List[Detection]:
        """Analyze .env file for exposed credentials and tech hints."""
        detections: List[Detection] = []
        content_lower = content.lower()
        
        # This is CRITICAL - exposed env file with secrets
        detections.append(
            Detection(
                name="Exposed Environment File",
                category="Configuration",
                confidence=1.0,
                evidence=Evidence(
                    type="env_file",
                    value=endpoint,
                    name="Exposed .env with potential secrets"
                ),
                version=None
            )
        )
        
        # Detect technologies from env variable names
        tech_hints = {
            "database_url|db_host|mysql|postgresql|mongodb": "Database",
            "redis_url|redis_host": "Redis Cache",
            "aws_access_key|aws_secret": "AWS",
            "google_api": "Google Cloud",
            "stripe_key|stripe_secret": "Stripe Payment",
            "github_token": "GitHub Integration",
            "slack_token": "Slack Integration",
            "sendgrid_api": "SendGrid Email",
            "twilio": "Twilio SMS",
        }
        
        for pattern, tech_name in tech_hints.items():
            if any(hint in content_lower for hint in pattern.split("|")):
                detections.append(
                    Detection(
                        name=tech_name,
                        category="External Service",
                        confidence=0.9,
                        evidence=Evidence(
                            type="env_file",
                            value=endpoint,
                            name=f"Detected in .env file"
                        ),
                        version=None
                    )
                )
        
        return detections

    def _analyze_package_manifest(self, endpoint: str, content: str) -> List[Detection]:
        """Analyze package.json, composer.json, requirements.txt for dependencies."""
        detections: List[Detection] = []
        path = endpoint.split('/')[-1]
        
        if 'package.json' in path:
            # Node.js project
            detections.append(
                Detection(
                    name="Node.js",
                    category="Runtime",
                    confidence=0.95,
                    evidence=Evidence(
                        type="package_manifest",
                        value=endpoint,
                        name="Exposed package.json"
                    ),
                    version=None
                )
            )
            
            # Try to detect frameworks from dependencies
            frameworks = {
                "react": "React",
                "angular": "Angular",
                "vue": "Vue.js",
                "express": "Express.js",
                "fastify": "Fastify",
                "next": "Next.js",
                "nuxt": "Nuxt.js",
                "svelte": "Svelte",
                "gatsby": "Gatsby",
            }
            
            for dep, framework in frameworks.items():
                if f'"{dep}"' in content.lower() or f"'{dep}'" in content.lower():
                    detections.append(
                        Detection(
                            name=framework,
                            category="Framework",
                            confidence=0.9,
                            evidence=Evidence(
                                type="package_manifest",
                                value=endpoint,
                                name=f"Dependency in package.json"
                            ),
                            version=None
                        )
                    )
        
        elif 'composer.json' in path:
            # PHP project
            detections.append(
                Detection(
                    name="PHP",
                    category="Language",
                    confidence=0.95,
                    evidence=Evidence(
                        type="package_manifest",
                        value=endpoint,
                        name="Exposed composer.json"
                    ),
                    version=None
                )
            )
        
        elif 'requirements.txt' in path:
            # Python project
            detections.append(
                Detection(
                    name="Python",
                    category="Language",
                    confidence=0.95,
                    evidence=Evidence(
                        type="package_manifest",
                        value=endpoint,
                        name="Exposed requirements.txt"
                    ),
                    version=None
                )
            )
        
        return detections

    def _analyze_config_file(self, endpoint: str, content: str) -> List[Detection]:
        """Analyze config files (.htaccess, web.config, etc) for tech hints."""
        detections: List[Detection] = []
        path = endpoint.split('/')[-1]
        
        if '.htaccess' in path:
            detections.append(
                Detection(
                    name="Apache HTTP Server",
                    category="Web Server",
                    confidence=0.95,
                    evidence=Evidence(
                        type="config_file",
                        value=endpoint,
                        name="Exposed .htaccess"
                    ),
                    version=None
                )
            )
        
        elif 'web.config' in path:
            detections.append(
                Detection(
                    name="Microsoft IIS",
                    category="Web Server",
                    confidence=0.95,
                    evidence=Evidence(
                        type="config_file",
                        value=endpoint,
                        name="Exposed web.config"
                    ),
                    version=None
                )
            )
        
        elif 'dockerfile' in path.lower() or 'docker-compose' in path.lower():
            detections.append(
                Detection(
                    name="Docker",
                    category="Container",
                    confidence=0.95,
                    evidence=Evidence(
                        type="config_file",
                        value=endpoint,
                        name="Exposed Docker configuration"
                    ),
                    version=None
                )
            )
        
        return detections

    @staticmethod
    def _get_file_type(path: str) -> str:
        """Determine file type from path."""
        path_lower = path.lower()
        
        if '.git' in path_lower:
            return "git_config"
        elif '.env' in path_lower:
            return "env_file"
        elif any(x in path_lower for x in ['package.json', 'composer.json', 'requirements.txt', 'gemfile', 'pom.xml']):
            return "package_manifest"
        else:
            return "config_file"

    @staticmethod
    def _load_leak_paths() -> List[str]:
        """Load source code leak paths from configuration."""
        config = load_config("rules/source_code_leaks.yaml")
        return config.get("leak_paths", [])
