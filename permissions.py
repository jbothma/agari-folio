PERMISSIONS = {
    # System admin
    "system_admin_access": ["system-admin"],
    
    # Organization management
    # TODO: Not implemented yet
    "create_org": ["system-admin"],
    "delete_org": ["system-admin"],
    "manage_org_settings": ["system-admin", "agari-org-owner"],

    # Organization members management
    # TODO: Not implemented yet
    "invite_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "add_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "remove_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "change_org_member_roles": ["system-admin", "agari-org-owner", "agari-org-admin"],

    # Pathogen management
    "create_pathogen": ["system-admin"],
    "edit_pathogen": ["system-admin"],
    "delete_pathogen": ["system-admin"],
    "view_pathogens": [],

    # Project management
    "create_project": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "edit_projects": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "delete_projects": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "view_projects": [],
    "view_project_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "manage_project_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],

    # Study management
    "view_studies": ["system-admin","agari-org-owner", "agari-org-admin", "agari-org-viewer", "attr-project-admin", "attr-project-contributor", "attr-project-viewer"],   "create_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "edit_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "delete_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "list_study_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "manage_study_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "submit_to_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin", "attr-project-contributor", "attr-study-contributor"]
}