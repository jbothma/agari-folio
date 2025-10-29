from email import message
import os
import subprocess
import json
import hashlib
import requests
from flask import render_template_string
from auth import KeycloakAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To

from database import get_db_cursor


sg_api_key = os.getenv(
    "SENDGRID_API_KEY",
    "",
)
sg_from_email = os.getenv("SENDGRID_FROM_EMAIL", "webapps+agaridev@openup.org.za")
sg_from_name = os.getenv("SENDGRID_FROM_NAME", "AGARI")

sg = SendGridAPIClient(sg_api_key)

keycloak_auth = KeycloakAuth(
    keycloak_url=os.getenv("KEYCLOAK_URL", "http://keycloak.local"),
    realm=os.getenv("KEYCLOAK_REALM", "agari"),
    client_id=os.getenv("KEYCLOAK_CLIENT_ID", "dms"),
    client_secret=os.getenv(
        "KEYCLOAK_CLIENT_SECRET", "VDyLEjGR3xDQvoQlrHq5AB6OwbW0Refc"
    ),
)


def sendgrid_email(to_email, to_name, subject, html_content):
    message = Mail(
        from_email=From(sg_from_email, sg_from_name),
        to_emails=To(to_email, to_name),
        subject=subject,
        html_content=html_content,
    )
    response = sg.send(message)
    return response


def mjml_to_html(template_name):
    result = subprocess.run(
        ["mjml", f"email_templates/{template_name}.mjml", "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )
    html_template = result.stdout
    return html_template


def magic_link(email, redirect_uri, expiration_seconds=600, send_email=True):
    admin_token = keycloak_auth.get_admin_token()
    if not admin_token:
        return {"error": "Failed to authenticate with Keycloak admin"}, 500
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "client_id": keycloak_auth.client_id,
        "redirect_uri": redirect_uri,
        "expiration_seconds": expiration_seconds,
        "force_create": True,
        "reusable": False,
        "send_email": False,
    }
    magic_link_url = (
        f"{keycloak_auth.keycloak_url}/realms/{keycloak_auth.realm}/magic-link"
    )
    keycloak_response = requests.post(magic_link_url, headers=headers, json=payload)
    response_data = json.loads(keycloak_response.content.decode("utf-8"))

    if send_email:
        # Manually send magic link
        html_template = mjml_to_html("magic_link")
        html_content = render_template_string(
            html_template, magic_link=response_data["link"]
        )
        sendgrid_email(email, "", "Your AGARI sign-in link", html_content)
        message = "Magic link sent successfully"
    else:
        message = "Magic link created successfully (email not sent)"

    if keycloak_response.status_code == 200:
        response_data = keycloak_response.json()
        return {
            "message": message,
            "email": email,
            "user_id": response_data.get("user_id"),
        }, 200
    else:
        return {"error": f"Failed to create magic link."}, 500


def quiet_create_user(email, redirect_uri):
    keycloak_response = magic_link(email, redirect_uri, 0, False)

    return keycloak_response


def invite_user_to_project(user, redirect_uri, project_id, role):
    if user.get("attributes"):
        name = user["attributes"].get("name", [""])[0]
        surname = user["attributes"].get("surname", [""])[0]
        to_name = f"{name} {surname}".strip()
    else:
        to_name = ""
    to_email = user["email"]
    subject = "You've been invited to AGARI"

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM projects
            WHERE id = %s AND deleted_at IS NULL
        """,
            (project_id),
        )
        project = cursor.fetchone()
        if not project:
            return {"error": "Project not found"}, 404

    hash_string = f"{user['id']}{project_id}"
    inv_token = hashlib.md5(hash_string.encode()).hexdigest()
    accept_link = (
        f"{redirect_uri}/accept-invite-project?userid={user['id']}&token={inv_token}"
    )

    html_template = mjml_to_html("project_invite")
    html_content = render_template_string(
        html_template, project_name=project["name"], accept_link=accept_link
    )

    response = sendgrid_email(to_email, to_name, subject, html_content)

    if response.status_code in [200, 201, 202]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user["id"], "invite_token", inv_token)
        keycloak_auth.add_attribute_value(user["id"], "invite_project_id", project_id)
        keycloak_auth.add_attribute_value(user["id"], "invite_role", role)
        return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500


def invite_user_to_org(user, redirect_uri, org_id, role):
    if user.get("attributes"):
        name = user["attributes"].get("name", [""])[0]
        surname = user["attributes"].get("surname", [""])[0]
        to_name = f"{name} {surname}".strip()
    else:
        to_name = ""
    to_email = user["email"]

    subject = "You've been invited to AGARI"

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM organisations
            WHERE id = %s AND deleted_at IS NULL
        """,
            (org_id),
        )
        org = cursor.fetchone()
        if not org:
            return {"error": "Organisation not found"}, 404

    hash_string = f"{user['id']}{org_id}"
    inv_token = hashlib.md5(hash_string.encode()).hexdigest()
    accept_link = (
        f"{redirect_uri}/accept-invite-org?userid={user['id']}&token={inv_token}"
    )

    html_template = mjml_to_html("new_user")
    html_content = render_template_string(
        html_template, org_name=org["name"], accept_link=accept_link
    )

    response = sendgrid_email(to_email, to_name, subject, html_content)

    if response.status_code in [200, 201, 202]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user["id"], "invite_org_token", inv_token)
        keycloak_auth.add_attribute_value(user["id"], "invite_org_id", org_id)
        keycloak_auth.add_attribute_value(user["id"], "invite_org_role", role)
        return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500


def access_revoked_notification(user_id):
    user = keycloak_auth.get_user(user_id)

    to_email = user["email"]
    to_name = ""
    subject = "Regarding your AGARI account"

    html_template = mjml_to_html("revoke_access")
    html_content = render_template_string(html_template)

    sendgrid_email(to_email, to_name, subject, html_content)


def log_event(log_type, resource_id, log_entry):
    try:
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO logs (log_type, resource_id, log_entry)
                VALUES (%s, %s, %s)
                """,
                (log_type, resource_id, log_entry),
            )
            return True

    except Exception as e:
        print(f"Error saving submission log: {e}")
        return False


def log_submission(project_id, analysis_id, user_id, status, message):
    try:
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO submissions (project_id, analysis_id, user_id, status, message)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (project_id, analysis_id, user_id, status, json.dumps(message)),
            )
            return True

    except Exception as e:
        print(f"Error saving submission log: {e}")
        return False


def tsv_to_json(tsv_string):
    lines = tsv_string.strip().split("\n")
    headers = lines[0].split("\t")
    json_list = []

    for line in lines[1:]:
        values = line.split("\t")
        record = {headers[i]: values[i] for i in range(len(headers))}
        json_list.append(record)

    return json_list
