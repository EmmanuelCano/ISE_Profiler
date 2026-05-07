from __future__ import annotations

import argparse
import copy
import getpass
import json
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

warnings.filterwarnings(
    "ignore",
    message=r"urllib3 v2 only supports OpenSSL 1\.1\.1\+, currently the 'ssl' module is compiled with 'LibreSSL.*",
)

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None


DEFAULT_TIMEOUT = 60
APP_NAME = "cisco-ise-profiler-menu"

DIRECT_POLICY_EXAMPLE = [
    {
        "name": "RuleOne",
        "profilingType": "DIRECT",
        "status": True,
        "rulePriority": 1,
        "directMapRules": [
            {
                "matchedAttribute": {
                    "dictionaryName": "MDM",
                    "attributeValue": "mdmManufacturer"
                },
                "profileLabel": {
                    "dictionaryName": "Endpoint",
                    "attributeValue": "MFCInfoEndpointType"
                }
            }
        ]
    }
]

CUSTOM_POLICY_EXAMPLE = [
    {
        "name": "CustomPolicySample",
        "profilingType": "CUSTOM",
        "status": True,
        "rulePriority": 10,
        "profileLabel": {
            "dictionaryName": "Endpoint",
            "attributeValue": "MFCInfoEndpointType"
        },
        "condition": {
            "conditionType": "ConditionAndBlock",
            "children": [
                {
                    "conditionType": "ConditionAttributes",
                    "dictionaryName": "DHCP",
                    "attributeName": "dhcpHostName",
                    "attributeValue": "dhcpHostName",
                    "operator": "contains",
                    "value": "corp"
                }
            ]
        }
    }
]


@dataclass(frozen=True)
class ApiOperation:
    id: int
    category: str
    method: str
    path: str
    summary: str
    friendly_name: str = ""
    description: str = ""
    notes: str = ""
    requires_query_params: bool = False
    post_attributes: list[str] = field(default_factory=list)
    example_body: Optional[Any] = None
    default_query: dict[str, str] = field(default_factory=dict)


@dataclass
class ConnectionProfile:
    ise_host: str
    username: Optional[str] = None
    base_url: Optional[str] = None

    @property
    def profile_name(self) -> str:
        return self.ise_host

    @property
    def resolved_base_url(self) -> str:
        if self.base_url:
            return self.base_url
        return normalize_base_url(self.ise_host)


OPERATIONS = [
    ApiOperation(
        id=1,
        category="Profiler Policy Management",
        method="GET",
        path="/api/v1/profiler/endpoint-custom-dictionary",
        summary="Get endpoint custom dictionary",
        friendly_name="View custom dictionary keys",
        description="Returns custom dictionary keys that can be used to build profiler rules.",
    ),
    ApiOperation(
        id=2,
        category="Profiler Policy Management",
        method="GET",
        path="/api/v1/profiler/endpoint-direct-dictionary",
        summary="Get endpoint direct dictionary",
        friendly_name="View direct dictionary keys",
        description="Returns direct dictionary keys for device profiling and direct mapping rules.",
    ),
    ApiOperation(
        id=3,
        category="Profiler Policy Management",
        method="GET",
        path="/api/v1/profiler/policy",
        summary="Get policy",
        friendly_name="List profiler policies",
        description="Lists existing profiler policies with filtering options based on query parameters.",
    ),
    ApiOperation(
        id=4,
        category="Profiler Policy Management",
        method="PUT",
        path="/api/v1/profiler/policy",
        summary="Update policy",
        friendly_name="Update a profiler policy",
        requires_query_params=False,
        description="Updates one or more existing profiler policies.",
        notes="Body must be a JSON array. Each object must include profilingType and policyId.",
        example_body=[
            {
                "policyId": "REPLACE_WITH_POLICY_ID",
                "profilingType": "DIRECT",
                "name": "Updated Policy Name",
                "status": True,
                "rulePriority": 1,
                "directMapRules": [
                    {
                        "matchedAttribute": {"dictionaryName": "MDM", "attributeValue": "mdmManufacturer"},
                        "profileLabel": {"dictionaryName": "Endpoint", "attributeValue": "MFCInfoEndpointType"}
                    }
                ]
            }
        ],
    ),
    ApiOperation(
        id=5,
        category="Profiler Policy Management",
        method="POST",
        path="/api/v1/profiler/policy",
        summary="Create policy",
        friendly_name="Create a profiler policy",
        description="Creates DIRECT or CUSTOM profiler policies. Body must be a JSON array.",
        notes="Choose DIRECT or CUSTOM example when prompted, or paste your own JSON array payload.",
        post_attributes=[
            "name: Policy display name (string)",
            "profilingType: CUSTOM, DIRECT, or PROFILE (string)",
            "status: true or false (boolean)",
            "rulePriority: Evaluation order number (integer)",
            "profileLabel: Dictionary object for CUSTOM policies",
            "condition: ConditionAndBlock with children[] for CUSTOM policies",
            "directMapRules: Required mapping rules for DIRECT policies",
        ],
    ),
    ApiOperation(
        id=6,
        category="Profiler Policy Management",
        method="DELETE",
        path="/api/v1/profiler/policy",
        summary="Delete policy by ID",
        friendly_name="Delete a policy by ID",
        requires_query_params=False,
        description="Deletes one or more profiler policies by identifier.",
        notes="The OpenAPI UI shows delete-by-ID semantics on the same path. Supply the required ID as query parameter or body according to your ISE deployment.",
        example_body=["REPLACE_WITH_POLICY_ID"],
    ),
    ApiOperation(
        id=7,
        category="Profiler Policy Management",
        method="GET",
        path="/api/v1/profiler/policy-export",
        summary="Export policy JSON file",
        friendly_name="Export profiler policies",
        description="Exports profiler policies in JSON format for backup or migration.",
    ),
    ApiOperation(
        id=8,
        category="Profiler Policy Management",
        method="PUT",
        path="/api/v1/profiler/policy-status",
        summary="Update policy status by ID",
        friendly_name="Enable or disable a policy",
        requires_query_params=False,
        description="Enables or disables profiler policies without editing policy logic.",
        notes="Body must be a JSON array containing policyId and boolean status.",
        example_body=[
            {
                "policyId": "REPLACE_WITH_POLICY_ID",
                "status": True
            }
        ],
    ),
    ApiOperation(
        id=9,
        category="Profiler Policy Management",
        method="POST",
        path="/api/v1/profiler/policy/duplicate-check",
        summary="Check duplicate condition",
        friendly_name="Check for duplicate policy condition",
        description="Validates whether a proposed policy condition overlaps with an existing policy.",
        post_attributes=[
            "profilingType: CUSTOM, DIRECT, or PROFILE (string)",
            "condition: Condition object to check for duplicate matching",
            "excludePolicyId: Optional policy ID to exclude from duplicate check",
        ],
        example_body={
            "profilingType": "CUSTOM",
            "condition": {
                "conditionType": "ConditionAndBlock",
                "children": [
                    {
                        "conditionType": "ConditionAttributes",
                        "dictionaryName": "DHCP",
                        "attributeName": "dhcpHostName",
                        "attributeValue": "dhcpHostName",
                        "operator": "contains",
                        "value": "corp"
                    }
                ]
            }
        },
    ),

]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interactive Cisco ISE 3.5 profiler OpenAPI menu client."
    )
    parser.add_argument(
        "--ise-ip",
        help="Cisco ISE IP address or hostname. If you omit the scheme, HTTPS is assumed.",
    )
    parser.add_argument(
        "--base-url",
        help="Cisco ISE base URL, for example https://ise.example.com. Overrides --ise-ip.",
    )
    parser.add_argument(
        "--username",
        help="Username for Basic authentication.",
    )
    parser.add_argument(
        "--password",
        help="Password for Basic authentication. If omitted, prompt securely.",
    )
    parser.add_argument(
        "--token",
        help="Bearer token to use instead of Basic authentication.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="HTTP timeout in seconds. Default: 60.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification.",
    )
    parser.add_argument(
        "--auto-retry-insecure",
        action="store_true",
        help="If TLS verification fails, automatically retry with certificate verification disabled for this run.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the available profiler operations and exit.",
    )
    return parser


def normalize_base_url(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith(("http://", "https://")):
        return stripped.rstrip("/")
    return f"https://{stripped.rstrip('/')}"


def prompt_yes_no(label: str, default: bool = True) -> bool:
    prompt = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} ({prompt}): ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Enter y or n.")


def prompt_connection_profile(args: argparse.Namespace) -> ConnectionProfile:
    if args.base_url:
        host = args.ise_ip or args.base_url
        return ConnectionProfile(ise_host=host, username=args.username, base_url=normalize_base_url(args.base_url))

    if args.ise_ip:
        return ConnectionProfile(ise_host=args.ise_ip, username=args.username)

    ise_host = prompt_non_empty("ISE IP address or hostname")
    return ConnectionProfile(ise_host=ise_host, username=args.username)


def print_operations() -> None:
    print("Cisco ISE Profiler OpenAPI operations")
    print()
    for operation in OPERATIONS:
        friendly = operation.friendly_name or operation.summary
        print(f"  {operation.id}. {friendly}")
    print()


def json_to_table(data: any, max_rows: int = 50) -> str:
    """Convert JSON data to formatted table representation."""
    if not isinstance(data, (list, dict)):
        return str(data)
    
    # If it's a list of dicts, use tabulate if available
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if tabulate:
            return tabulate(data[:max_rows], headers="keys", tablefmt="grid")
        else:
            # Fallback: simple table-like format
            if len(data) > max_rows:
                data = data[:max_rows]
            lines = []
            if data:
                keys = list(data[0].keys())
                lines.append(" | ".join(str(k) for k in keys))
                lines.append("-" * (sum(len(str(k)) for k in keys) + len(keys) * 3))
                for row in data:
                    lines.append(" | ".join(str(row.get(k, "")) for k in keys))
            return "\n".join(lines)
    
    # For single dict or other types, use tabulate if available
    if isinstance(data, dict):
        if tabulate:
            return tabulate([(k, v) for k, v in list(data.items())[:max_rows]], headers=["Key", "Value"], tablefmt="grid")
        else:
            return json.dumps(data, indent=2)
    
    # Fallback to JSON
    return json.dumps(data, indent=2)


def save_get_response(operation: ApiOperation, response_data: any) -> Optional[str]:
    """Save GET response to a file and return the file path."""
    try:
        output_dir = Path.home() / ".config" / APP_NAME / "responses"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create filename from operation ID and timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        is_text = isinstance(response_data, str)
        ext = "txt" if is_text else "json"
        filename = f"response_{operation.id}_{timestamp}.{ext}"
        filepath = output_dir / filename

        with open(filepath, 'w') as f:
            if is_text:
                f.write(response_data)
            else:
                json.dump(response_data, f, indent=2)

        return str(filepath)
    except Exception as e:
        print(f"Warning: Could not save response to file: {e}")
        return None


def prompt_non_empty(label: str, default: Optional[str] = None, secret: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        if secret:
            value = getpass.getpass(f"{label}{suffix}: ")
        else:
            value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value:
            return value
        print("A value is required.")


def prompt_optional(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def select_operation() -> ApiOperation:
    print_operations()
    while True:
        choice = input("Select an operation number, or q to quit: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            raise SystemExit(0)
        if choice.isdigit():
            operation_id = int(choice)
            for operation in OPERATIONS:
                if operation.id == operation_id:
                    return operation
        print("Invalid selection.")


def prompt_query_params() -> dict[str, str]:
    params: dict[str, str] = {}
    print("Enter query parameters one per line as key=value. Press Enter on an empty line to finish.")
    while True:
        entry = input("query> ").strip()
        if not entry:
            break
        if "=" not in entry:
            print("Use key=value format.")
            continue
        key, value = entry.split("=", 1)
        params[key.strip()] = value.strip()
    return params


def prompt_json_body() -> Optional[Any]:
    print("Paste a JSON body. Press Enter on an empty line to skip. Finish with a line containing only END.")
    lines: list[str] = []
    first_line = input("json> ")
    if not first_line.strip():
        return None
    if first_line.strip() == "END":
        return None
    lines.append(first_line)
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)

    try:
        return json.loads("\n".join(lines))
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}")
        return prompt_json_body()


def prompt_create_policy_body() -> Optional[Any]:
    print("Create policy example type:")
    print("  1. DIRECT policy example")
    print("  2. CUSTOM policy example")
    print("  3. Paste JSON manually")
    while True:
        choice = input("Choose 1, 2, or 3 [1]: ").strip() or "1"
        if choice == "1":
            print("Example request body:")
            print(json.dumps(DIRECT_POLICY_EXAMPLE, indent=2))
            if prompt_yes_no("Use this DIRECT example body", default=True):
                return copy.deepcopy(DIRECT_POLICY_EXAMPLE)
            return prompt_json_body()
        if choice == "2":
            print("Example request body:")
            print(json.dumps(CUSTOM_POLICY_EXAMPLE, indent=2))
            if prompt_yes_no("Use this CUSTOM example body", default=True):
                return copy.deepcopy(CUSTOM_POLICY_EXAMPLE)
            return prompt_json_body()
        if choice == "3":
            return prompt_json_body()
        print("Invalid selection.")


def prompt_body_for_operation(operation: ApiOperation) -> Optional[Any]:
    if operation.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None

    if operation.id == 5:
        return prompt_create_policy_body()

    if operation.method == "POST":
        if operation.post_attributes:
            print("Recommended attributes for this POST call:")
            for item in operation.post_attributes:
                print(f"  - {item}")
            print()

    if operation.example_body is not None:
        print("Example request body:")
        print(json.dumps(operation.example_body, indent=2))
        if prompt_yes_no("Use this example body", default=True):
            return copy.deepcopy(operation.example_body)

    return prompt_json_body()


def build_session(args: argparse.Namespace, profile: ConnectionProfile) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    if args.token:
        session.headers["Authorization"] = f"Bearer {args.token}"
    else:
        username = args.username or profile.username or prompt_non_empty("ISE username")
        password = args.password
        if args.password:
            print("Warning: passing --password on the command line can expose secrets in shell history.")
            print("Prefer interactive entry instead.")
        if password is None:
            password = prompt_non_empty("ISE password", secret=True)
        session.auth = (username, password)
    return session


def _send_request(
    session: requests.Session,
    method: str,
    url: str,
    params: dict[str, str],
    body: Optional[Any],
    timeout: int,
    verify: bool,
) -> tuple[bool, Optional[requests.Response]]:
    """Send HTTP request and handle SSL errors with auto-retry."""
    try:
        if not verify:
            urllib3.disable_warnings(InsecureRequestWarning)
        response = session.request(
            method=method,
            url=url,
            params=params or None,
            json=body,
            timeout=timeout,
            verify=verify,
        )
        return verify, response
    except requests.exceptions.SSLError as exc:
        if verify:
            print(f"TLS verification failed (self-signed certificate detected). Retrying with verification disabled...")
            return _send_request(session, method, url, params, body, timeout, verify=False)
        print(f"TLS verification failed: {exc}")
        return verify, None
    except requests.RequestException as exc:
        print(f"Request failed: {exc}")
        return verify, None


def execute_operation(
    session: requests.Session,
    base_url: str,
    operation: ApiOperation,
    timeout: int,
    verify: bool,
    auto_retry_insecure: bool,
) -> bool:
    url = f"{base_url.rstrip('/')}{operation.path}"

    params = dict(operation.default_query)

    # Only prompt for query parameters if operation requires them
    if operation.requires_query_params:
        extra_params = prompt_query_params()
        params.update(extra_params)

    body = prompt_body_for_operation(operation)

    verify, response = _send_request(session, operation.method, url, params, body, timeout, verify)

    print()
    if response is None:
        print("Failed: no response received")
        print()
        return verify

    status = "Successful" if response.ok else "Failed"
    print(f"HTTP {response.status_code} - {status}")

    # For selected GET operations, also display the API response payload.
    if response.ok and operation.id in {1, 2, 3, 7}:
        content_type = response.headers.get("Content-Type", "")
        json_data = None
        if "application/json" in content_type:
            try:
                json_data = response.json()
            except ValueError:
                json_data = None

        print()
        print("API response:")
        if json_data is not None:
            print(json.dumps(json_data, indent=2))
        else:
            # Try parsing the text as JSON anyway (e.g. file-export endpoints set octet-stream)
            try:
                json_data = json.loads(response.text)
                print(json.dumps(json_data, indent=2))
            except (ValueError, TypeError):
                print(response.text)

        saved_path = save_get_response(operation, json_data if json_data is not None else response.text)
        if saved_path:
            print()
            print(f"Response saved to: {saved_path}")
    print()
    return verify


def main() -> int:
    args = build_parser().parse_args()

    if args.list:
        print_operations()
        return 0

    connection_profile = prompt_connection_profile(args)
    base_url = normalize_base_url(args.base_url) if args.base_url else connection_profile.resolved_base_url
    session = build_session(args, connection_profile)
    verify = not args.insecure

    try:
        while True:
            try:
                operation = select_operation()
            except SystemExit:
                print("Exiting.")
                return 0
            verify = execute_operation(
                session,
                base_url,
                operation,
                args.timeout,
                verify,
                args.auto_retry_insecure,
            )
            again = prompt_optional("Run another operation? (Y/n)", "y").lower()
            if again in {"n", "no"}:
                return 0
    except KeyboardInterrupt:
        print("\nExiting.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())