# AGARI RBAC API

A Flask application focused on implementing the AGARI Role-Based Access Control (RBAC) system based on Keycloak JWT tokens and user roles.

## Overview

This API provides a clean, permission-matrix-based approach to handling authorization in the AGARI system. It extracts user roles from Keycloak JWT tokens and maps them to specific permissions using a centralized permissions matrix.

## Roles

The system supports the following roles from Keycloak:

- **system-admin**: Global system administrator with all permissions
- **agari-org-owner**: Organisation owner with full organisation control  
- **agari-org-admin**: Organisation administrator with member management
- **agari-project-admin**: Project administrator with project-specific control
- **agari-contributor**: Can contribute data to assigned projects
- **agari-viewer**: Read-only access to assigned projects

## Permissions Matrix

The core of the RBAC system is the permissions matrix defined in `permissions.py`. It maps each permission to the roles that can perform it:

```python
PERMISSIONS_MATRIX = {
    "create_pathogen": ["system-admin"],
    "create_project": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "upload_data": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor"],
    # ... etc
}
```

## Key Features

1. **JWT Token Authentication**: Validates and extracts user information from Keycloak JWT tokens
2. **Role-Based Permissions**: Maps user roles to specific permissions  
3. **Permission Checking**: Provides endpoints to check user permissions
4. **Swagger Documentation**: Auto-generated API documentation
5. **Test Suite**: Comprehensive testing with different user roles

## API Endpoints

### Authentication
- `GET /auth/whoami` - Get current user information
- `GET /auth/user` - Get detailed user info with permissions

### Permissions  
- `GET /permissions/check/{permission}` - Check if user has specific permission
- `GET /permissions/matrix` - Get complete permissions matrix
- `GET /permissions/my-permissions` - Get all permissions for current user

### Health
- `GET /health` - Health check endpoint

## Running the Application

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5001` with Swagger documentation at `http://localhost:5001/docs/`.

### Docker

1. Build the image:
```bash
docker build -t agari-rbac .
```

2. Run the container:
```bash
docker run -p 5001:5001 agari-rbac
```

### k3d Deployment (Recommended)

For deployment to the AGARI k3d cluster:

1. Ensure your k3d cluster named `agari` is running
2. Deploy the application:
```bash
./deploy.sh
```

3. Test the deployment:
```bash
./test-deployment.sh
```

The deployment script will:
- Build the Docker image
- Import it to the k3d cluster
- Deploy using Helm to the `agari` namespace
- Set up ingress at `http://rbac.local/`

### Manual k3d Deployment

If you prefer manual deployment:

```bash
# Build and import image
docker build -t ghcr.io/openupsa/agari-rbac:latest .
k3d image import ghcr.io/openupsa/agari-rbac:latest -c agari

# Deploy with Helm
kubectl config use-context k3d-agari
helm install agari-rbac ./helm -n agari --create-namespace

# Port-forward for testing
kubectl port-forward svc/agari-rbac 5001:80 -n agari
```

## Testing

The application includes a comprehensive test suite that demonstrates RBAC functionality:

```bash
# Run the test suite
python test_rbac.py

# View the permissions matrix
python test_rbac.py matrix
```

## Environment Variables

- `KEYCLOAK_HOST`: Keycloak server URL (default: `http://keycloak:8080`)
- `KEYCLOAK_REALM`: Keycloak realm name (default: `agari`)
- `KEYCLOAK_ISSUER`: JWT token issuer URL

## Authentication

The API expects JWT tokens in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

The JWT token should contain:
- `preferred_username`: User's username
- `email`: User's email address  
- `organisation_id`: User's organisation ID
- `realm_access.roles`: Array of user's roles

## Example Usage

```python
import requests

headers = {
    'Authorization': 'Bearer <your_jwt_token>',
    'Content-Type': 'application/json'
}

# Check if user can create projects
response = requests.get(
    'http://localhost:5001/permissions/check/create_project',
    headers=headers
)

if response.json()['granted']:
    print("User can create projects!")
```

## Integration with Existing System

This RBAC API is designed to work alongside the existing AGARI Folio API. It can be:

1. **Used as a standalone service** for permission checking
2. **Integrated into existing services** by importing the permissions module
3. **Extended with additional permissions** as needed

## Future Enhancements

- Project-specific role assignments
- Dynamic permission assignment
- Audit logging
- Role hierarchy management
- Integration with Keycloak admin API
