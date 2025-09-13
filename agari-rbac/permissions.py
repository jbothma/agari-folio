"""
AGARI Permissions Matrix

This module defines the permissions matrix that maps each action/permission
to the roles that are allowed to perform it.

Based on the RBAC specification and Keycloak realm configuration.
"""

# Permissions matrix - maps permissions to roles that can perform them
PERMISSIONS_MATRIX = {
    # System-wide permissions
    "system_admin_access": ["system-admin"],
    
    # Organisation management
    "create_organisation": ["system-admin"],
    "delete_organisation": ["system-admin"],
    "manage_organisation_settings": ["system-admin", "agari-org-owner"],
    "transfer_organisation_ownership": ["system-admin", "agari-org-owner"],
    "view_organisation_activity_log": ["system-admin", "agari-org-owner", "agari-org-admin"],
    
    # Member management
    "manage_all_organisation_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "invite_organisation_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "remove_organisation_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "change_member_roles": ["system-admin", "agari-org-owner", "agari-org-admin"],
    
    # Project management
    "create_project": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "delete_project": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "manage_project_settings": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "manage_project_members": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "invite_project_members": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    
    # Data submission management
    "view_all_submissions": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "view_own_submissions": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor"],
    "upload_data": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor"],
    "publish_own_draft_submissions": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor"],
    "publish_any_draft_submission": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    
    # Data access
    "view_published_sample_data": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor", "agari-viewer"],
    "download_published_sample_data": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor", "agari-viewer"],
    "view_sample_data_from_own_drafts": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor"],
    "view_sample_data_from_all_drafts": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    
    # Pathogen management (system admin only in current setup)
    "create_pathogen": ["system-admin"],
    "edit_pathogen": ["system-admin"],
    "delete_pathogen": ["system-admin"],
    "view_pathogens": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor", "agari-viewer"],
    
    # Study management
    "create_study": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "edit_study": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "delete_study": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    "manage_study_members": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin"],
    
    # Read-only access
    "view_projects": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor", "agari-viewer"],
    "view_studies": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-project-admin", "agari-contributor", "agari-viewer"],
}


def get_user_permissions(user_roles):
    """
    Get all permissions for a user based on their roles.
    
    Args:
        user_roles (list): List of role names the user has
        
    Returns:
        set: Set of permission names the user has
    """
    user_permissions = set()
    
    for permission, allowed_roles in PERMISSIONS_MATRIX.items():
        # Check if user has any of the roles that grant this permission
        if any(role in user_roles for role in allowed_roles):
            user_permissions.add(permission)
    
    return user_permissions


def has_permission(user_roles, permission):
    """
    Check if a user has a specific permission.
    
    Args:
        user_roles (list): List of role names the user has
        permission (str): Permission name to check
        
    Returns:
        bool: True if user has the permission, False otherwise
    """
    allowed_roles = PERMISSIONS_MATRIX.get(permission, [])
    return any(role in user_roles for role in allowed_roles)


def get_roles_with_permission(permission):
    """
    Get all roles that have a specific permission.
    
    Args:
        permission (str): Permission name to check
        
    Returns:
        list: List of role names that have this permission
    """
    return PERMISSIONS_MATRIX.get(permission, [])


def get_permissions_for_role(role):
    """
    Get all permissions for a specific role.
    
    Args:
        role (str): Role name
        
    Returns:
        list: List of permission names the role has
    """
    permissions = []
    for permission, allowed_roles in PERMISSIONS_MATRIX.items():
        if role in allowed_roles:
            permissions.append(permission)
    return permissions
