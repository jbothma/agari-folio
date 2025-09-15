import jwt
import requests
from functools import wraps
from flask import request, jsonify
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

class KeycloakAuth:
    def __init__(self, keycloak_url, realm, client_id, client_secret):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.public_key = None
        
    def get_public_key(self):
        """Fetch public key from Keycloak for token verification"""
        try:
            certs_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid_connect/certs"
            response = requests.get(certs_url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching public key: {e}")
            return None
    
    def verify_token(self, token):
        """Extract user info from JWT token without signature verification"""
        try:
            # Decode token without signature verification for internal services
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
            
        except Exception as e:
            return {'error': f'Token decode failed: {str(e)}'}
    
    def get_admin_token(self):
        """Get admin access token for Keycloak API calls using service account"""
        try:
            token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            token_data = response.json()
            return token_data.get('access_token')
        except requests.RequestException as e:
            print(f"Error getting admin token: {e}")
            return None
    
    def get_users_by_attribute(self, attribute_name, attribute_value, exact_match=True):
        """
        Search for users by a specific attribute
        
        Args:
            attribute_name (str): The name of the attribute to search for
            attribute_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            list: List of users with simplified format (user_id, username, organisation_id, roles, attributes)
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return []
        
        try:
            # Keycloak admin API endpoint for users
            users_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            # For custom attributes, we need to get all users and filter client-side
            # as Keycloak's search doesn't handle custom attributes well
            params = {'max': 1000}
            
            response = requests.get(users_url, headers=headers, params=params)
            response.raise_for_status()
            
            users = response.json()
            
            # Filter users based on attribute
            filtered_users = []
            for user in users:
                if self._user_has_attribute_value(user, attribute_name, attribute_value, exact_match):
                    # Format user data similar to whoami response
                    user_data = self._format_user_data(user)
                    filtered_users.append(user_data)
            
            return filtered_users
            
        except requests.RequestException as e:
            print(f"Error searching users by attribute: {e}")
            return []
    
    def _user_has_attribute_value(self, user, attribute_name, attribute_value, exact_match=True):
        """
        Check if a user has a specific attribute value (supports comma-separated values)
        
        Args:
            user (dict): User object from Keycloak
            attribute_name (str): The name of the attribute to check
            attribute_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            bool: True if user has the attribute value, False otherwise
        """
        user_attributes = user.get('attributes', {})
        
        if attribute_name not in user_attributes:
            return False
        
        attr_values = user_attributes[attribute_name]
        
        # Attributes are stored as lists in Keycloak
        if isinstance(attr_values, list):
            for attr_val in attr_values:
                if self._check_attribute_value(str(attr_val), attribute_value, exact_match):
                    return True
        else:
            return self._check_attribute_value(str(attr_values), attribute_value, exact_match)
        
        return False
    
    def _check_attribute_value(self, attr_val, search_value, exact_match=True):
        """
        Check if an attribute value matches the search value (supports comma-separated values)
        
        Args:
            attr_val (str): The attribute value to check
            search_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            bool: True if there's a match, False otherwise
        """
        # Check if attribute value contains comma-separated values
        if ',' in attr_val:
            individual_values = [v.strip() for v in attr_val.split(',')]
            if exact_match:
                return search_value in individual_values
            else:
                return any(search_value.lower() in v.lower() for v in individual_values)
        else:
            # Single value check
            if exact_match:
                return search_value == attr_val
            else:
                return search_value.lower() in attr_val.lower()
    
    def _format_user_data(self, user):
        """
        Format user data similar to whoami response
        
        Args:
            user (dict): User object from Keycloak
            
        Returns:
            dict: Formatted user data with user_id, username, organisation_id, roles, attributes
        """
        # Extract custom attributes (excluding standard ones)
        user_attributes = {}
        attributes = user.get('attributes', {})
        
        for key, value in attributes.items():
            if key != 'organisation_id':  # organisation_id is handled separately
                user_attributes[key] = value
        
        return {
            'user_id': user.get('id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'organisation_id': attributes.get('organisation_id', [None])[0] if attributes.get('organisation_id') else None,
            'roles': [],  # Roles would need to be fetched separately if needed
            'attributes': user_attributes,
            'is_authenticated': True,
        }
    
    def user_has_attribute(self, user_id, attribute_name, attribute_value, exact_match=True):
        """
        Check if a specific user has an attribute with a given value
        
        Args:
            user_id (str): The user ID to check
            attribute_name (str): The name of the attribute to check
            attribute_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            bool: True if user has the attribute value, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get specific user by ID
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            return self._user_has_attribute_value(user, attribute_name, attribute_value, exact_match)
            
        except requests.RequestException as e:
            print(f"Error checking user attribute: {e}")
            return False
    
    def get_users_by_organization(self, organization_id):
        """
        Get all users belonging to a specific organization
        
        Args:
            organization_id (str): The organization ID to search for
            
        Returns:
            list: List of users in the organization
        """
        return self.get_users_by_attribute('organisation_id', organization_id)
    
    def get_users_by_role(self, role_name):
        """
        Get all users with a specific role
        
        Args:
            role_name (str): The role name to search for
            
        Returns:
            list: List of users with simplified format (user_id, username, organisation_id, roles, attributes)
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return []
        
        try:
            # Get role members endpoint
            role_users_url = f"{self.keycloak_url}/admin/realms/{self.realm}/roles/{role_name}/users"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(role_users_url, headers=headers)
            response.raise_for_status()
            
            users = response.json()
            
            # Format users similar to whoami response
            formatted_users = []
            for user in users:
                user_data = self._format_user_data(user)
                user_data['roles'] = [role_name]  # Add the specific role we searched for
                formatted_users.append(user_data)
            
            return formatted_users
            
        except requests.RequestException as e:
            print(f"Error getting users by role: {e}")
            return []

    def add_attribute_value(self, user_id, attribute_name, value_to_add):
        """
        Add a value to a user's attribute (supports comma-separated values)
        
        Args:
            user_id (str): The user ID to update
            attribute_name (str): The name of the attribute (e.g., 'project-admin', 'study-contributor')
            value_to_add (str): The value to add (e.g., project ID or study ID)
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            attributes = user.get('attributes', {})
            
            # Get current attribute values
            current_values = []
            if attribute_name in attributes:
                attr_values = attributes[attribute_name]
                if isinstance(attr_values, list):
                    # Join all list items and split by comma to handle mixed formats
                    for attr_val in attr_values:
                        current_values.extend([v.strip() for v in str(attr_val).split(',') if v.strip()])
                else:
                    current_values = [v.strip() for v in str(attr_values).split(',') if v.strip()]
            
            # Add new value if not already present
            if value_to_add not in current_values:
                current_values.append(value_to_add)
            
            # Store as comma-separated string in a list (Keycloak format)
            attributes[attribute_name] = [','.join(current_values)] if current_values else []
            user['attributes'] = attributes
            
            # Send update request
            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()
            
            return True
            
        except requests.RequestException as e:
            print(f"Error adding attribute value: {e}")
            return False
    
    def remove_attribute_value(self, user_id, attribute_name, value_to_remove):
        """
        Remove a value from a user's attribute (supports comma-separated values)
        
        Args:
            user_id (str): The user ID to update
            attribute_name (str): The name of the attribute (e.g., 'project-admin', 'study-contributor')
            value_to_remove (str): The value to remove (e.g., project ID or study ID)
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            attributes = user.get('attributes', {})
            
            # Get current attribute values
            current_values = []
            if attribute_name in attributes:
                attr_values = attributes[attribute_name]
                if isinstance(attr_values, list):
                    # Join all list items and split by comma to handle mixed formats
                    for attr_val in attr_values:
                        current_values.extend([v.strip() for v in str(attr_val).split(',') if v.strip()])
                else:
                    current_values = [v.strip() for v in str(attr_values).split(',') if v.strip()]
            
            # Remove the value if present
            if value_to_remove in current_values:
                current_values.remove(value_to_remove)
            
            # Store as comma-separated string in a list (Keycloak format)
            # If no values left, remove the attribute entirely
            if current_values:
                attributes[attribute_name] = [','.join(current_values)]
            elif attribute_name in attributes:
                del attributes[attribute_name]
            
            user['attributes'] = attributes
            
            # Send update request
            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()
            
            return True
            
        except requests.RequestException as e:
            print(f"Error removing attribute value: {e}")
            return False

def require_auth(keycloak_auth):
    """Decorator to require authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                return {'error': 'No authorization header'}, 401
            
            try:
                token = auth_header.split(' ')[1]  # Remove 'Bearer ' prefix
            except IndexError:
                return {'error': 'Invalid authorization header format'}, 401
            
            user_info = keycloak_auth.verify_token(token)
            
            if not user_info or 'error' in user_info:
                error_msg = user_info.get('error', 'Token verification failed') if user_info else 'Token verification failed'
                return {'error': error_msg}, 401
            
            # Add user info to request context
            request.user = user_info
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def extract_user_info(token_payload):
    """Extract useful user information from JWT payload"""
    
    realm_roles = []
    if "realm_access" in token_payload and "roles" in token_payload["realm_access"]:
        realm_roles = token_payload["realm_access"]["roles"]
    
    # Extract user attributes - they can be in different places in the JWT
    user_attributes = {}
    
    standard_claims = {
        'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'typ', 'azp',
        'session_state', 'acr', 'allowed-origins', 'realm_access', 'resource_access',
        'scope', 'sid', 'email_verified', 'name', 'preferred_username', 'given_name',
        'family_name', 'email', 'groups'
    }
    
    for key, value in token_payload.items():
        if key not in standard_claims and not key.startswith(('realm_', 'resource_')):
            user_attributes[key] = value

    return {
        'user_id': token_payload.get('sub'),
        'username': token_payload.get('preferred_username'),
        'email': token_payload.get('email'),
        'organisation_id': token_payload.get('organisation_id'),
        'roles': realm_roles,
        'attributes': user_attributes,
        'is_authenticated': True,
    }

def check_user_permission(user_info, permission_name, permissions_dict):
    """Check if user has a specific permission"""
    user_roles = user_info.get('roles', [])
    required_roles = permissions_dict.get(permission_name, [])
    return any(role in required_roles for role in user_roles)

def require_permission_or_attribute(permission_name, permissions_dict, attribute_name=None, attribute_value_param=None):
    """
    Decorator to require either a specific permission OR a specific attribute value
    
    Args:
        permission_name (str): The permission name to check
        permissions_dict (dict): The permissions configuration
        attribute_name (str): The attribute name to check (e.g., 'project-admin')
        attribute_value_param (str): The parameter name in the route that contains the attribute value (e.g., 'project_id')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return {'error': 'Authentication required'}, 401
            
            user_info = extract_user_info(request.user)
            
            # First check if user has the general permission
            if check_user_permission(user_info, permission_name, permissions_dict):
                return f(*args, **kwargs)
            
            # If no general permission, check attribute-based access
            if attribute_name and attribute_value_param:
                # Get the attribute value from the route parameters
                attribute_value = kwargs.get(attribute_value_param)
                if not attribute_value:
                    return {'error': 'Missing required parameter for attribute check'}, 400
                
                user_id = user_info.get('user_id')
                if not user_id:
                    return {'error': 'User ID not found in token'}, 401
                
                # We need access to the keycloak_auth instance - let's get it from the global scope
                # This is a bit of a hack, but necessary for the decorator pattern
                from flask import current_app
                keycloak_auth = getattr(current_app, 'keycloak_auth', None)
                
                if not keycloak_auth:
                    return {'error': 'Keycloak authentication not configured'}, 500
                
                # Check if user has the specific attribute value
                if keycloak_auth.user_has_attribute(user_id, attribute_name, attribute_value):
                    return f(*args, **kwargs)
            
            # If neither permission nor attribute check passed
            return {
                'error': 'Insufficient permissions',
                'required_permission': permission_name,
                'user_roles': user_info.get('roles', []),
                'required_roles': permissions_dict.get(permission_name, []),
                'attribute_check': f'{attribute_name}={attribute_value}' if attribute_name and attribute_value_param else None
            }, 403
        
        return decorated_function
    return decorator

def require_permission(permission_name, permissions_dict):
    """Decorator to require a specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'user'):
                return {'error': 'Authentication required'}, 401
            
            user_info = extract_user_info(request.user)
            
            if not check_user_permission(user_info, permission_name, permissions_dict):
                return {
                    'error': 'Insufficient permissions',
                    'required_permission': permission_name,
                    'user_roles': user_info.get('roles', []),
                    'required_roles': permissions_dict.get(permission_name, [])
                }, 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def require_organization_access(permission_name, permissions_dict, resource_id_param, 
                              attribute_names=None, allow_public=False, allow_system_admin=True):
    """
    Decorator to require organization-based access control with proper permission AND organization logic
    
    This decorator implements the correct access control logic:
    1. If public resource AND allow_public=True → Allow anyone (even unauthenticated)
    2. If system-admin → Allow (bypasses all restrictions)
    3. If has permission AND same organization → Allow
    4. If has ANY of the specified attributes for this resource → Allow
    5. Otherwise → Deny
    
    Args:
        permission_name (str): The permission name to check (e.g., 'list_project_users')
        permissions_dict (dict): The permissions configuration
        resource_id_param (str): The parameter name in the route that contains the resource ID (e.g., 'project_id')
        attribute_names (list, optional): List of attribute names to check (e.g., ['project-admin', 'project-contributor', 'project-viewer'])
        allow_public (bool): Whether to allow unauthenticated access for public resources (default: False)
        allow_system_admin (bool): Whether system-admin can bypass all restrictions (default: True)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get the resource ID from route parameters
            resource_id = kwargs.get(resource_id_param)
            if not resource_id:
                return {'error': f'Missing required parameter: {resource_id_param}'}, 400
            
            # Get resource information from database (including privacy setting)
            try:
                from database import get_db_cursor
                
                # Determine the table name based on resource_id_param
                if resource_id_param == 'project_id':
                    table_name = 'projects'
                    id_column = 'id'
                elif resource_id_param == 'study_id':
                    table_name = 'studies'
                    id_column = 'id'
                else:
                    # Default to projects for now
                    table_name = 'projects'
                    id_column = 'id'
                
                with get_db_cursor() as cursor:
                    cursor.execute(f"""
                        SELECT organisation_id, privacy 
                        FROM {table_name} 
                        WHERE {id_column} = %s AND deleted_at IS NULL
                    """, (resource_id,))
                    
                    resource = cursor.fetchone()
                    
                    if not resource:
                        return {'error': f'{table_name.rstrip("s").title()} not found'}, 404
                    
                    resource_org_id = resource['organisation_id']
                    is_public_resource = resource.get('privacy') == 'public'
                    
            except Exception as e:
                return {'error': f'Database error during organization check: {str(e)}'}, 500
            
            # 1. Check if public resource and public access is allowed
            if allow_public and is_public_resource:
                return f(*args, **kwargs)
            
            # For all other checks, authentication is required
            if not hasattr(request, 'user'):
                return {'error': 'Authentication required'}, 401
            
            user_info = extract_user_info(request.user)
            user_org_id = user_info.get('organisation_id')
            user_roles = user_info.get('roles', [])
            user_id = user_info.get('user_id')
            
            # 2. Check if user is system admin (bypass all restrictions if allowed)
            is_system_admin = 'system-admin' in user_roles
            if allow_system_admin and is_system_admin:
                return f(*args, **kwargs)
            
            # 3. Check if user has permission AND same organization
            if check_user_permission(user_info, permission_name, permissions_dict):
                if user_org_id and user_org_id == resource_org_id:
                    return f(*args, **kwargs)
            
            # 4. Check attribute-based access (if any attribute_names provided)
            if attribute_names and user_id:
                from flask import current_app
                keycloak_auth = getattr(current_app, 'keycloak_auth', None)
                
                if keycloak_auth:
                    # Check if user has ANY of the specified attributes for this resource
                    for attribute_name in attribute_names:
                        if keycloak_auth.user_has_attribute(user_id, attribute_name, resource_id):
                            return f(*args, **kwargs)
            
            # 5. If none of the access checks passed, deny access
            return {
                'error': 'Insufficient permissions',
                'required_permission': permission_name,
                'user_roles': user_roles,
                'required_roles': permissions_dict.get(permission_name, []),
                'attribute_checks': attribute_names if attribute_names else None,
                'organization_access': f'User org: {user_org_id}, Resource org: {resource_org_id}',
                'resource_privacy': 'public' if is_public_resource else 'private',
                'public_access_allowed': allow_public
            }, 403
        
        return decorated_function
    return decorator


