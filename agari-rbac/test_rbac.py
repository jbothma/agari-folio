"""
AGARI RBAC Test Script

This script demonstrates how to test the RBAC functionality with different user roles.
"""

import requests
import json
import jwt
from datetime import datetime, timedelta


def create_test_jwt(username, email, organisation_id, roles):
    """
    Create a test JWT token for a user with specific roles.
    
    Note: This is for testing only. In production, tokens come from Keycloak.
    """
    payload = {
        'sub': f'test-{username}',
        'preferred_username': username,
        'email': email,
        'name': f'Test {username.title()}',
        'given_name': 'Test',
        'family_name': username.title(),
        'organisation_id': organisation_id,
        'realm_access': {
            'roles': roles
        },
        'iss': 'http://keycloak:8080/realms/agari',
        'aud': 'dms',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
    }
    
    # Create unsigned token for testing
    token = jwt.encode(payload, 'secret', algorithm='HS256')
    return token


def test_rbac_api(base_url='http://localhost:5001'):
    """Test the RBAC API with different user roles"""
    
    # Test users with different roles
    test_users = [
        {
            'name': 'System Admin',
            'username': 'system.admin@agari.tech',
            'email': 'system.admin@agari.tech',
            'organisation_id': 'system',
            'roles': ['system-admin', 'offline_access', 'uma_authorization']
        },
        {
            'name': 'Org Owner',
            'username': 'owner@org1.ac.za',
            'email': 'owner@org1.ac.za',
            'organisation_id': 'org1',
            'roles': ['agari-org-owner', 'offline_access']
        },
        {
            'name': 'Org Admin',
            'username': 'org-admin@org1.ac.za',
            'email': 'org-admin@org1.ac.za',
            'organisation_id': 'org1',
            'roles': ['agari-org-admin', 'offline_access']
        },
        {
            'name': 'Project Admin',
            'username': 'project-admin@org1.ac.za',
            'email': 'project-admin@org1.ac.za',
            'organisation_id': 'org1',
            'roles': ['agari-project-admin', 'offline_access']
        },
        {
            'name': 'Contributor',
            'username': 'contributor@org1.ac.za',
            'email': 'contributor@org1.ac.za',
            'organisation_id': 'org1',
            'roles': ['agari-contributor', 'offline_access']
        },
        {
            'name': 'Viewer',
            'username': 'viewer@org1.ac.za',
            'email': 'viewer@org1.ac.za',
            'organisation_id': 'org1',
            'roles': ['agari-viewer', 'offline_access']
        }
    ]
    
    print("AGARI RBAC API Test Results")
    print("=" * 50)
    
    # Test key permissions for each user
    test_permissions = [
        'create_pathogen',
        'create_project',
        'manage_organisation_settings',
        'upload_data',
        'view_published_sample_data'
    ]
    
    for user in test_users:
        print(f"\n{user['name']} ({user['username']})")
        print("-" * 30)
        
        # Create JWT token for this user
        token = create_test_jwt(
            user['username'],
            user['email'],
            user['organisation_id'],
            user['roles']
        )
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        try:
            # Test whoami endpoint
            response = requests.get(f'{base_url}/auth/whoami', headers=headers)
            if response.status_code == 200:
                data = response.json()
                print(f"Roles: {data.get('roles', [])}")
                print(f"Organisation: {data.get('organisation_id', 'N/A')}")
            else:
                print(f"Auth failed: {response.status_code}")
                continue
            
            # Test permissions
            print("Permissions:")
            for permission in test_permissions:
                response = requests.get(f'{base_url}/permissions/check/{permission}', headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    status = "✓" if data.get('granted') else "✗"
                    print(f"  {status} {permission}")
                else:
                    print(f"  ? {permission} (error: {response.status_code})")
            
            # Get all permissions for this user
            response = requests.get(f'{base_url}/permissions/my-permissions', headers=headers)
            if response.status_code == 200:
                data = response.json()
                print(f"Total permissions: {data.get('permission_count', 0)}")
            
        except Exception as e:
            print(f"Error testing {user['name']}: {e}")


def print_permissions_matrix():
    """Print the permissions matrix in a readable format"""
    from permissions import PERMISSIONS_MATRIX
    
    print("\nAGARI Permissions Matrix")
    print("=" * 50)
    
    # Group permissions by category
    categories = {
        'System': ['system_admin_access'],
        'Organisation': [p for p in PERMISSIONS_MATRIX.keys() if 'organisation' in p],
        'Member Management': [p for p in PERMISSIONS_MATRIX.keys() if 'member' in p],
        'Project': [p for p in PERMISSIONS_MATRIX.keys() if 'project' in p],
        'Data Submission': [p for p in PERMISSIONS_MATRIX.keys() if 'submission' in p or 'upload' in p or 'publish' in p],
        'Data Access': [p for p in PERMISSIONS_MATRIX.keys() if 'view' in p or 'download' in p],
        'Pathogen': [p for p in PERMISSIONS_MATRIX.keys() if 'pathogen' in p],
        'Study': [p for p in PERMISSIONS_MATRIX.keys() if 'study' in p],
    }
    
    for category, permissions in categories.items():
        if permissions:
            print(f"\n{category}:")
            for permission in permissions:
                if permission in PERMISSIONS_MATRIX:
                    roles = PERMISSIONS_MATRIX[permission]
                    print(f"  {permission}: {roles}")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'matrix':
        print_permissions_matrix()
    else:
        print("Starting RBAC API test...")
        print("Make sure the API is running on http://localhost:5001")
        print()
        test_rbac_api()
        print_permissions_matrix()
