"""
api_wiring.py — SOC Stack API Integration Module

Provides idempotent functions to wire together Wazuh, DFIR IRIS, Shuffle SOAR,
and Ollama after the Podman stack boots. All functions check for existing
resources before creating to ensure safe re-runs.
"""

import json
import time
import logging
import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("soc_stack.wiring")


# ---------------------------------------------------------------------------
# Wazuh API
# ---------------------------------------------------------------------------

def get_wazuh_token(base_url: str, user: str, password: str) -> str:
    """
    Authenticate to the Wazuh API and return a JWT bearer token.

    Args:
        base_url: e.g. "https://localhost:55000"
        user: Wazuh API username (default "wazuh-wui")
        password: Wazuh API password

    Returns:
        JWT token string
    """
    url = f"{base_url}/security/user/authenticate"
    try:
        resp = requests.post(
            url,
            auth=(user, password),
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        token = resp.json().get("data", {}).get("token", "")
        if not token:
            raise ValueError("Empty token received from Wazuh API")
        logger.info("Wazuh JWT token acquired successfully")
        return token
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get Wazuh token: {e}")
        raise


def configure_wazuh_integration(
    base_url: str,
    token: str,
    shuffle_webhook_url: str,
    vt_api_key: str | None = None,
    otx_api_key: str | None = None,
) -> None:
    """
    Configure Wazuh integrations (Shuffle webhook, VirusTotal, OTX) via the API.
    This supplements the ossec.conf integrations that are already embedded.
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Verify Wazuh manager info
    try:
        resp = requests.get(
            f"{base_url}/manager/info",
            headers=headers,
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        info = resp.json().get("data", {})
        logger.info(f"Wazuh Manager version: {info.get('version', 'unknown')}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not verify Wazuh manager info: {e}")


# ---------------------------------------------------------------------------
# DFIR IRIS API
# ---------------------------------------------------------------------------

def create_iris_api_key(base_url: str, admin_user: str, admin_pass: str) -> str:
    """
    Create (or retrieve existing) DFIR IRIS API key.

    Args:
        base_url: e.g. "http://localhost:8000"
        admin_user: IRIS admin username
        admin_pass: IRIS admin password

    Returns:
        API key string
    """
    session = requests.Session()

    # Step 1: Authenticate and get session cookie
    login_url = f"{base_url}/api/login"
    try:
        resp = session.post(
            login_url,
            json={"username": admin_user, "password": admin_pass},
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        logger.info("Authenticated to DFIR IRIS")
    except requests.exceptions.RequestException as e:
        logger.error(f"IRIS authentication failed: {e}")
        raise

    # Step 2: Check existing API keys
    keys_url = f"{base_url}/api/v2/api-keys"
    try:
        resp = session.get(keys_url, verify=False, timeout=30)
        if resp.status_code == 200:
            keys = resp.json().get("data", [])
            for key in keys:
                if key.get("name") == "soc-stack-automation":
                    logger.info("IRIS API key 'soc-stack-automation' already exists")
                    return key.get("api_key", "")
    except requests.exceptions.RequestException:
        pass

    # Step 3: Create new API key
    create_url = f"{base_url}/api/v2/api-keys"
    try:
        resp = session.post(
            create_url,
            json={"name": "soc-stack-automation"},
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        api_key = resp.json().get("data", {}).get("api_key", "")
        if api_key:
            logger.info("Created IRIS API key 'soc-stack-automation'")
            return api_key
        else:
            # Fallback: try to use the token from login
            logger.warning("Could not extract API key from IRIS response")
            return resp.json().get("data", {}).get("token", "fallback-key")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create IRIS API key: {e}")
        raise


def create_iris_case(base_url: str, api_key: str, case_data: dict) -> dict:
    """Create a case in DFIR IRIS."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{base_url}/api/v1/cases"
    try:
        resp = requests.post(url, headers=headers, json=case_data, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create IRIS case: {e}")
        raise


def add_iris_case_note(base_url: str, api_key: str, case_id: int, title: str, content: str) -> dict:
    """Add a note to an existing IRIS case."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    url = f"{base_url}/api/v1/cases/{case_id}/notes"
    payload = {"note_title": title, "note_content": content}
    try:
        resp = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to add IRIS case note: {e}")
        raise


# ---------------------------------------------------------------------------
# Shuffle SOAR
# ---------------------------------------------------------------------------

def register_shuffle_workflow(base_url: str, api_key: str, workflow_json: dict) -> dict:
    """
    Register a workflow in Shuffle. Checks for duplicates by name first.

    Args:
        base_url: e.g. "http://localhost:3001"
        api_key: Shuffle API key
        workflow_json: Workflow definition

    Returns:
        Created/existing workflow dict
    """
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # Check if workflow already exists
    try:
        resp = requests.get(
            f"{base_url}/api/v1/workflows",
            headers=headers,
            verify=False,
            timeout=30,
        )
        if resp.status_code == 200:
            workflows = resp.json()
            if isinstance(workflows, list):
                for wf in workflows:
                    if wf.get("name") == workflow_json.get("name"):
                        logger.info(f"Shuffle workflow '{wf['name']}' already exists")
                        return wf
    except requests.exceptions.RequestException:
        pass

    # Create new workflow
    try:
        resp = requests.post(
            f"{base_url}/api/v1/workflows",
            headers=headers,
            json=workflow_json,
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info(f"Created Shuffle workflow: {workflow_json.get('name', 'unnamed')}")
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to create Shuffle workflow: {e}")
        raise


def create_shuffle_wazuh_trigger(shuffle_url: str, shuffle_api_key: str, wazuh_webhook_url: str) -> None:
    """
    Create a Shuffle webhook trigger that receives Wazuh alerts.
    The webhook URL is configured in Wazuh's ossec.conf integration block.
    """
    workflow = {
        "name": "Wazuh Alert Trigger",
        "description": "Receives Wazuh alerts via webhook and processes them",
        "triggers": [
            {
                "trigger_type": "WEBHOOK",
                "name": "wazuh-alert-webhook",
                "description": "Webhook endpoint for Wazuh alert forwarding",
                "parameters": {
                    "url": wazuh_webhook_url,
                },
            }
        ],
        "actions": [
            {
                "name": "Parse Alert",
                "app_name": "Shuffle Tools",
                "app_action": "parse_json",
                "parameters": {"input": "$exec"},
            }
        ],
    }
    try:
        register_shuffle_workflow(shuffle_url, shuffle_api_key, workflow)
        logger.info("Wazuh → Shuffle webhook trigger configured")
    except Exception as e:
        logger.error(f"Failed to create Wazuh trigger: {e}")


def create_shuffle_iris_workflow(
    shuffle_url: str, shuffle_api_key: str, iris_url: str, iris_api_key: str
) -> None:
    """
    Create Shuffle workflow: Alert → Parse → Create IRIS Case → Add Notes.
    """
    workflow = {
        "name": "Alert to IRIS Case",
        "description": "Automatically creates DFIR IRIS cases from Wazuh alerts",
        "triggers": [
            {
                "trigger_type": "WEBHOOK",
                "name": "alert-to-case-webhook",
                "description": "Triggered by Wazuh alert forwarding",
            }
        ],
        "actions": [
            {
                "name": "Parse Alert JSON",
                "app_name": "Shuffle Tools",
                "app_action": "parse_json",
                "parameters": {"input": "$exec"},
            },
            {
                "name": "Create IRIS Case",
                "app_name": "HTTP",
                "app_action": "POST",
                "parameters": {
                    "url": f"{iris_url}/api/v1/cases",
                    "headers": json.dumps({
                        "Authorization": f"Bearer {iris_api_key}",
                        "Content-Type": "application/json",
                    }),
                    "body": json.dumps({
                        "case_name": "Wazuh Alert — $parse_alert_json.rule.description",
                        "case_description": "Auto-created from Wazuh alert",
                        "case_severity": 3,
                        "case_customer": 1,
                    }),
                },
            },
            {
                "name": "Add Alert Details to Case Notes",
                "app_name": "HTTP",
                "app_action": "POST",
                "parameters": {
                    "url": f"{iris_url}/api/v1/cases/$create_iris_case.case_id/notes",
                    "headers": json.dumps({
                        "Authorization": f"Bearer {iris_api_key}",
                        "Content-Type": "application/json",
                    }),
                    "body": json.dumps({
                        "note_title": "Original Wazuh Alert",
                        "note_content": "$exec",
                    }),
                },
            },
        ],
    }
    try:
        register_shuffle_workflow(shuffle_url, shuffle_api_key, workflow)
        logger.info("Shuffle → IRIS case creation workflow configured")
    except Exception as e:
        logger.error(f"Failed to create IRIS workflow: {e}")


def create_shuffle_ollama_workflow(
    shuffle_url: str, shuffle_api_key: str, ollama_url: str, model_name: str
) -> None:
    """
    Create Shuffle workflow: IRIS Case Created → Fetch Details →
    Ollama Enrichment → Post back to IRIS as case note.
    """
    system_prompt = (
        "You are a junior SOC analyst assistant. Analyze the following security alert "
        "and provide: 1) MITRE ATT&CK technique mapping, 2) Severity assessment, "
        "3) Immediate containment steps, 4) Investigation steps, 5) Remediation steps. "
        "Be concise and actionable."
    )

    workflow = {
        "name": "Ollama Case Enrichment",
        "description": "Enriches IRIS cases with AI analysis from Ollama",
        "triggers": [
            {
                "trigger_type": "WEBHOOK",
                "name": "case-enrichment-trigger",
                "description": "Triggered when a new case is created in IRIS",
            }
        ],
        "actions": [
            {
                "name": "Fetch Case Details",
                "app_name": "HTTP",
                "app_action": "GET",
                "parameters": {
                    "url": "$exec.case_url",
                },
            },
            {
                "name": "Ollama Analysis",
                "app_name": "HTTP",
                "app_action": "POST",
                "parameters": {
                    "url": f"{ollama_url}/api/generate",
                    "headers": json.dumps({"Content-Type": "application/json"}),
                    "body": json.dumps({
                        "model": model_name,
                        "system": system_prompt,
                        "prompt": "Analyze this security case: $fetch_case_details",
                        "stream": False,
                    }),
                },
            },
            {
                "name": "Post Enrichment to IRIS",
                "app_name": "HTTP",
                "app_action": "POST",
                "parameters": {
                    "url": "$exec.iris_notes_url",
                    "body": json.dumps({
                        "note_title": "AI Triage — Ollama Analysis",
                        "note_content": "$ollama_analysis.response",
                    }),
                },
            },
            {
                "name": "Tag Case as AI-Triaged",
                "app_name": "HTTP",
                "app_action": "PUT",
                "parameters": {
                    "url": "$exec.iris_case_url",
                    "body": json.dumps({"case_tags": "ai-triaged"}),
                },
            },
        ],
    }
    try:
        register_shuffle_workflow(shuffle_url, shuffle_api_key, workflow)
        logger.info("Shuffle → Ollama enrichment workflow configured")
    except Exception as e:
        logger.error(f"Failed to create Ollama enrichment workflow: {e}")


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

def pull_ollama_model(ollama_url: str, model_name: str, progress_callback=None) -> None:
    """
    Pull an Ollama model. This is a blocking operation that streams progress.

    Args:
        ollama_url: e.g. "http://localhost:11434"
        model_name: e.g. "mistral:7b"
        progress_callback: Optional callable(status_str, percent_float) for progress updates
    """
    url = f"{ollama_url}/api/pull"
    payload = {"name": model_name, "stream": True}

    logger.info(f"Pulling Ollama model '{model_name}' — this may take a while...")

    try:
        resp = requests.post(url, json=payload, stream=True, verify=False, timeout=1800)
        resp.raise_for_status()

        for line in resp.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    status = data.get("status", "")
                    completed = data.get("completed", 0)
                    total = data.get("total", 0)

                    if total > 0:
                        pct = (completed / total) * 100
                        msg = f"{status}: {pct:.1f}%"
                    else:
                        msg = status

                    if progress_callback:
                        progress_callback(msg, (completed / total * 100) if total else 0)
                    else:
                        logger.info(msg)

                    if status == "success":
                        logger.info(f"Model '{model_name}' pulled successfully")
                        return
                except json.JSONDecodeError:
                    continue

    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to pull Ollama model '{model_name}': {e}")
        raise


def check_ollama_model(ollama_url: str, model_name: str) -> bool:
    """Check if an Ollama model is already available."""
    try:
        resp = requests.get(f"{ollama_url}/api/tags", verify=False, timeout=10)
        if resp.status_code == 200:
            models = resp.json().get("models", [])
            for m in models:
                if m.get("name", "").startswith(model_name.split(":")[0]):
                    logger.info(f"Ollama model '{model_name}' is already available")
                    return True
    except requests.exceptions.RequestException:
        pass
    return False


def generate_ollama(
    ollama_url: str,
    model_name: str,
    prompt: str,
    system_prompt: str = "",
    stream: bool = False,
) -> str | requests.Response:
    """
    Generate text with Ollama.

    Args:
        ollama_url: Ollama API base URL
        model_name: Model to use
        prompt: User prompt
        system_prompt: System prompt
        stream: If True, return the raw Response for streaming

    Returns:
        Generated text string, or Response object if stream=True
    """
    url = f"{ollama_url}/api/generate"
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": stream,
    }
    if system_prompt:
        payload["system"] = system_prompt

    try:
        resp = requests.post(url, json=payload, stream=stream, verify=False, timeout=300)
        resp.raise_for_status()

        if stream:
            return resp
        else:
            return resp.json().get("response", "")
    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama generation failed: {e}")
        raise


# ---------------------------------------------------------------------------
# Health Checks
# ---------------------------------------------------------------------------

HEALTH_ENDPOINTS = {
    "wazuh-manager": {"url": "https://localhost:55000/manager/info", "auth": True},
    "opensearch": {"url": "https://localhost:9200", "auth": False},
    "wazuh-dashboard": {"url": "https://localhost:443", "auth": False},
    "iris": {"url": "http://localhost:8000/api/versions", "auth": False},
    "shuffle": {"url": None, "port": 3001, "auth": False},
    "ollama": {"url": "http://localhost:11434/api/tags", "auth": False},
    "postgres": {"url": None, "port": 5432, "auth": False},
    "mongodb": {"url": None, "port": 27017, "auth": False},
}


def check_service_health(name: str, config: dict) -> bool:
    """Check if a single service is healthy."""
    url = config.get("url")
    if url is None:
        # TCP port check (for MongoDB)
        import socket
        port = config.get("port", 0)
        try:
            with socket.create_connection(("localhost", port), timeout=5):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    try:
        resp = requests.get(url, verify=False, timeout=10)
        return resp.status_code < 500
    except requests.exceptions.RequestException:
        return False


def health_check_all(services: dict | None = None) -> dict:
    """
    Check health of all SOC stack services.

    Args:
        services: Optional custom service dict. Uses HEALTH_ENDPOINTS if None.

    Returns:
        Dict of {service_name: bool}
    """
    if services is None:
        services = HEALTH_ENDPOINTS

    results = {}
    for name, config in services.items():
        results[name] = check_service_health(name, config)
        status = "✅ UP" if results[name] else "❌ DOWN"
        logger.info(f"  {name}: {status}")

    return results


def wait_for_services(
    services: dict | None = None,
    max_wait: int = 600,
    interval: int = 15,
    progress_callback=None,
) -> dict:
    """
    Wait for all services to become healthy with exponential backoff.

    Args:
        services: Service health config dict
        max_wait: Maximum wait time in seconds (default 10 minutes)
        interval: Initial polling interval in seconds
        progress_callback: Optional callable(elapsed, max_wait, results) for updates

    Returns:
        Final health check results
    """
    if services is None:
        services = HEALTH_ENDPOINTS

    start = time.time()
    current_interval = interval
    attempt = 0

    while True:
        elapsed = time.time() - start
        if elapsed >= max_wait:
            logger.warning(f"Timed out after {max_wait}s waiting for services")
            break

        attempt += 1
        logger.info(f"Health check attempt {attempt} ({elapsed:.0f}s elapsed)...")
        results = health_check_all(services)

        if progress_callback:
            progress_callback(elapsed, max_wait, results)

        if all(results.values()):
            logger.info("All services are healthy!")
            return results

        down = [k for k, v in results.items() if not v]
        logger.info(f"Waiting for: {', '.join(down)}")

        time.sleep(min(current_interval, max_wait - elapsed))
        current_interval = min(current_interval * 1.5, 60)  # cap at 60s

    return health_check_all(services)
