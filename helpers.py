import os
import subprocess
import json
from flask import render_template_string
from auth import KeycloakAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To

# from app import keycloak_auth

sg_api_key = os.getenv(
    "SENDGRID_API_KEY",
    "",
)
sg_from_email = os.getenv("SENDGRID_FROM_EMAIL", "webapps+agaridev@openup.org.za")
sg_from_name = os.getenv("SENDGRID_FROM_NAME", "AGARI")
frontend_url = os.getenv("FRONTEND_URL", "https://agari-staging.openup.org.za")

sg = SendGridAPIClient(sg_api_key)

keycloak_auth = KeycloakAuth(
    keycloak_url=os.getenv("KEYCLOAK_URL", "http://keycloak.local"),
    realm=os.getenv("KEYCLOAK_REALM", "agari"),
    client_id=os.getenv("KEYCLOAK_CLIENT_ID", "dms"),
    client_secret=os.getenv(
        "KEYCLOAK_CLIENT_SECRET", "VDyLEjGR3xDQvoQlrHq5AB6OwbW0Refc"
    ),
)


def invite_user_to_project(user, project_id, role):
    to_email = user["email"]
    to_name = user["firstName"] + " " + user["lastName"]
    project_name = "test proj"  # project.get("name")
    subject = "You've been invited to AGARI"

    import hashlib

    inv_token = hashlib.md5(user["id"].encode()).hexdigest()
    accept_link = f"{frontend_url}/accept-invite?userid={user["id"]}&token={inv_token}"

    result = subprocess.run(
        ["mjml", "email_templates/user_invite.mjml", "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )
    html_template = result.stdout
    html_content = render_template_string(
        html_template, project_name=project_name, accept_link=accept_link
    )

    message = Mail(
        from_email=From(sg_from_email, sg_from_name),
        to_emails=To(to_email, to_name),
        subject=subject,
        html_content=html_content,
    )
    response = sg.send(message)

    if response.status_code in [200, 201, 202]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user["id"], "invite_token", inv_token)
        keycloak_auth.add_attribute_value(user["id"], "project_id", project_id)
        keycloak_auth.add_attribute_value(user["id"], "new_role", role)
        return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500


def invite_new_user_to_project(email, project):
    data = request.get_json()
    if not data:
        return {"error": "No JSON data provided"}, 400

    email = data.get("email")
    if not email:
        return {"error": "Email is required"}, 400

    # Create account with magic link plugin
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
        "redirect_uri": frontend_url,
        "expiration_seconds": 0,
        "force_create": True,
        "reusable": False,
        "send_email": False,
    }
    magic_link_url = (
        f"{keycloak_auth.keycloak_url}/realms/{keycloak_auth.realm}/magic-link"
    )
    keycloak_response = requests.post(
        magic_link_url, headers=headers, json=payload
    ).json()

    print("______________________________")
    # kc_response = keycloak_response.content.json()
    user_id = keycloak_response.get("user_id")
    print(user_id)
    import hashlib

    inv_token = hashlib.md5(user_id.encode()).hexdigest()
    html_content = f"{frontend_url}/accept-invite?userid={user_id}&token={inv_token}"

    result = subprocess.run(
        ["mjml", "email_templates/user_invite.mjml", "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )

    html_template = result.stdout
    html_content = render_template_string(
        html_template,
        name="Michael",
        organisation_name="Test org",
        action_url="https://yourapp.com/get-started",
    )

    message = Mail(
        from_email=From(sg_from_email, sg_from_name),
        to_emails=To(email, "to_name"),
        subject="Welcome to our platform!",
        html_content=html_content,
    )

    # message = Mail(
    #    from_email=From(self.from_email, self.from_name),
    #    to_emails=To(email, to_name),
    #    subject=Subject(subject),
    #    html_content=HtmlContent(html_content)
    # )

    response = sg.send(message)

    if response.status_code in [200, 201, 202]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user_id, "invite_token", inv_token)
        return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500
