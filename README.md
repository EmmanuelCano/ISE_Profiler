# ISE Profiler OpenAPI

An interactive menu-driven CLI tool for managing Cisco ISE 3.5 Profiler policies and operations. This tool simplifies interactions with the Cisco ISE Profiler OpenAPI by providing an intuitive interface to view, create, update, and delete profiling policies without complex REST API calls.

## Features

- **Interactive menu interface** - Navigate through operations using a user-friendly menu
- **Policy management** - Create, update, delete, and list profiling policies
- **Multiple authentication methods** - Support for Basic Auth and Bearer tokens
- **Secure credential storage** - Passwords stored in OS keychain (not plaintext)
- **Postman integration** - Includes pre-built Postman collection for API testing
- **Flexible connectivity** - Works with both fully-qualified domain names and IP addresses
- **TLS retry capability** - Automatic retry with insecure mode if needed

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/EmmanuelCano/ISE_Profiler.git
cd ISE_Profiler
python3 -m pip install -r requirements.txt
```

## Usage

### List available operations:

```bash
python3 ise_profiler.py --list
```

This displays all 10 supported profiler API operations.

### Start the interactive menu:

```bash
python3 ise_profiler.py --base-url https://your-ise-host.example.com
```

You'll be prompted to enter your ISE credentials and can then select operations from the menu.

### Using with bearer token authentication:

```bash
python3 ise_profiler.py --base-url https://your-ise-host.example.com --token YOUR_BEARER_TOKEN
```

### Automatically retry with insecure TLS:

```bash
python3 ise_profiler.py --base-url https://your-ise-host.example.com --auto-retry-insecure
```

This is useful if your ISE instance uses self-signed certificates.

## Postman Integration

A Postman collection is included for API testing and documentation:

- **Collection**: `ISE_Profiler_OpenAPI.postman_collection.json` (10 profiler endpoints)
- **Environment**: `ISE_Profiler.postman_environment.json` (variables and credentials)

To use with Postman:
1. Import both the collection and environment into Postman
2. Update the environment variables: `baseUrl`, `username`, `password`
3. Run requests directly or use Newman for automation

## Supported Operations

The tool supports 10 profiler API operations:

1. View custom dictionary keys
2. View direct dictionary keys
3. List profiler policies
4. Update profiler policy
5. Create custom profiler policy
6. Create direct profiler policy
7. Delete profiler policy by ID
8. Export profiler policies
9. Enable/disable profiler policy
10. Check for duplicate policy conditions

## How It Works

- **Interactive prompts** - The script guides you through each operation with clear prompts
- **JSON payload generation** - For complex operations, you can provide or modify JSON payloads
- **Live preview** - Before executing, you can review the request being sent
- **Profile persistence** - Your ISE connection details are saved locally (credentials stored securely)
- **Error handling** - Clear error messages help troubleshoot connectivity or API issues

## Security Notes

- Passwords are never saved to disk in plaintext
- If you choose password storage, it uses your OS keychain (macOS Keychain, Windows Credential Manager, or Linux Secret Service)
- Saved profiles only store ISE hostname and username
- Token-based authentication is supported for enhanced security

---

## Author

**Emmanuel Cano** - Customer Delivery Security Architect 
**LinkedIn:** https://linkedin.com/in/emmanuel-cano
