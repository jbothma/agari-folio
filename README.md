# Folio API - AGARI Genomics Data Management

Complete CRUD API for managing genomics research data with JWT authentication, role-based access control, and Keycloak integration.

## Overview

Folio provides a comprehensive REST API for managing genomics research data with:
- **JWT Authentication**: Secure token-based authentication via Keycloak
- **Role-based Access Control**: Granular permissions with `folio.READ` and `folio.WRITE` scopes
- **Complete CRUD Operations**: Full Create, Read, Update, Delete operations for all entities
- **Soft Deletes**: All delete operations preserve data integrity with timestamp-based soft deletion
- **Cascade Protection**: Prevents deletion of entities with dependencies
- **Keycloak Integration**: Automatic project and study group creation and user management

## Entity Hierarchy

```
Pathogens (managed by super users)
└── Projects (with read/write/admin groups)
    └── Studies (with read/write/admin groups)
```

## Permission Model

- **Public Access**: Anyone with valid token can view pathogens
- **Super User (`folio.WRITE`)**: Can create/edit/delete pathogens, projects, and studies
- **Project Members**: Automatic group-based permissions (read/write/admin) for project access
- **Study Members**: Automatic group-based permissions (read/write/admin) for study access
- **Data Protection**: Cascade deletion prevention maintains referential integrity

## API Endpoints

### Health
- `GET /health` - Health check endpoint

### Pathogens
- `GET /pathogens` - List all pathogens
- `POST /pathogens` - Create a new pathogen
- `GET /pathogens/{pathogen_id}` - Get pathogen details
- `PUT /pathogens/{pathogen_id}` - Update pathogen
- `DELETE /pathogens/{pathogen_id}` - Delete pathogen (soft delete)

### Projects
- `GET /projects` - List all projects
- `POST /projects` - Create a new project
- `GET /projects/{project_id}` - Get project details  
- `PUT /projects/{project_id}` - Update project
- `DELETE /projects/{project_id}` - Delete project (soft delete)

#### Project Management
- `POST /projects/{project_slug}/resource` - Create Keycloak resource for project
- `GET /projects/{project_slug}/resource` - Get project resource details
- `POST /projects/{project_slug}/group` - Create Keycloak group for project
- `GET /projects/{project_slug}/group` - Get project group details
- `GET /projects/{project_slug}/group/members` - Get project group members
- `POST /projects/{project_slug}/group/members/{username}` - Add user to project group
- `DELETE /projects/{project_slug}/group/members/{username}` - Remove user from project group
- `POST /projects/{project_slug}/users` - Add user to project with permissions
- `GET /projects/{project_slug}/studies` - Get studies for a project
- `GET /projects/{project_slug}/summary` - Get project summary with statistics

### Studies
- `GET /studies` - List all studies
- `POST /studies` - Create a new study
- `GET /studies/{study_id}` - Get study details
- `PUT /studies/{study_id}` - Update study
- `DELETE /studies/{study_id}` - Delete study (soft delete)

#### Study Management
- `POST /studies/{study_id}/resource` - Create Keycloak resource for study
- `GET /studies/{study_id}/resource` - Get study resource details
- `POST /studies/{study_id}/group` - Create Keycloak group for study
- `GET /studies/{study_id}/group` - Get study group details
- `GET /studies/{study_id}/group/members` - Get study group members
- `POST /studies/{study_id}/group/members/{username}` - Add user to study group
- `DELETE /studies/{study_id}/group/members/{username}` - Remove user from study group
- `POST /studies/{study_id}/users` - Add user to study with permissions

## Keycloak Integration

When projects and studies are created, Folio automatically:
1. Creates UMA resources in Keycloak
2. Creates corresponding groups with appropriate permissions
3. Manages user group membership
4. Handles resource-based authorization

## Documentation

Swagger documentation is available at `/docs/` when the service is running.