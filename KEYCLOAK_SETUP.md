# Keycloak Setup Guide

Detailed instructions for configuring Keycloak for ZTForensics.

---

## Automated Setup (recommended)

```bash
bash scripts/setup_keycloak.sh
```

If the automated setup fails, follow the manual steps below.

---

## Manual Setup

### 1. Access the Keycloak Admin Console

Navigate to **http://localhost:8080/admin** and log in with:
- Username: `admin` (or `KEYCLOAK_ADMIN_USER`)
- Password: `admin123` (or `KEYCLOAK_ADMIN_PASSWORD`)

### 2. Create the Realm

1. Click **Create Realm** in the left sidebar.
2. Set **Realm name** to `forensics`.
3. Enable the realm (toggle → On).
4. Click **Create**.

### 3. Create the Client

1. Navigate to **Clients** → **Create client**.
2. Set **Client ID** to `api-gateway`.
3. Set **Client type** to `OpenID Connect`.
4. Click **Next**.
5. Enable **Client authentication** (makes it a confidential client).
6. Enable **Service accounts roles**.
7. Enable **Direct access grants** (for testing with the password grant).
8. Click **Save**.

### 4. Get the Client Secret

1. Open the `api-gateway` client.
2. Go to the **Credentials** tab.
3. Copy the **Client secret** value.
4. Add it to your `.env` file:

```env
KEYCLOAK_CLIENT_SECRET=<copied-value>
```

### 5. Configure Token Audience

To include the client in the `aud` claim of the access token:

1. Go to the `api-gateway` client → **Client scopes** tab.
2. Click **api-gateway-dedicated**.
3. Click **Add mapper** → **By configuration** → **Audience**.
4. Name it `api-gateway-audience`.
5. Set **Included Client Audience** to `api-gateway`.
6. Enable **Add to access token**.
7. Click **Save**.

### 6. Create Realm Roles

Navigate to **Realm roles** → **Create role** for each of the following:

| Role | Description |
|---|---|
| `investigator` | Can view and export all forensic evidence |
| `analyst` | Can view evidence; cannot export |
| `auditor` | Read-only access to audit logs |
| `admin` | Full administrative access |
| `viewer` | Limited read-only access |

### 7. Create a Test User

1. Navigate to **Users** → **Add user**.
2. Set **Username** to `testuser`.
3. Set **Email** to `testuser@ztforensics.local`.
4. Enable **Email verified**.
5. Click **Create**.
6. Go to the **Credentials** tab → **Set password**.
7. Set password to `testpass123` with **Temporary** set to **Off**.
8. Go to the **Role mapping** tab → **Assign role** → select `investigator`.

---

## Token Configuration

### Access Token Lifetime

1. Go to **Realm settings** → **Tokens** tab.
2. Set **Access Token Lifespan** to `1 hour` (or as required by your security policy).

### Refresh Token

1. On the same **Tokens** tab, configure **Client Session Idle** and **Client Session Max** as appropriate.

---

## Scope Mapping

To include the user's roles in the JWT token:

1. Go to **Client scopes** → `roles` → **Mappers**.
2. Ensure **realm roles** mapper is enabled with **Add to access token** set to **On**.

---

## Frequently Asked Questions

**Q: Why is the token validation failing?**
- Ensure `KEYCLOAK_SERVER_URL` points to the correct Keycloak instance.
- Verify the realm name (`KEYCLOAK_REALM`) matches the one you created.
- Check that the client secret is correct in your `.env` file.
- Confirm that the `api-gateway` client has `Direct access grants` enabled for password-grant testing.

**Q: How do I get a token for testing?**

```bash
curl -s -X POST \
  "http://localhost:8080/realms/forensics/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=api-gateway" \
  -d "client_secret=<YOUR_CLIENT_SECRET>" \
  -d "username=testuser" \
  -d "password=testpass123" \
  | python3 -m json.tool
```

**Q: How do I add a custom claim to the token?**

1. Go to the `api-gateway` client → **Client scopes** → `api-gateway-dedicated`.
2. Click **Add mapper** → **By configuration** → **User Attribute** (or **Hardcoded claim**).
3. Configure the claim and save.

**Q: The setup script says "Realm may already exist". Is that a problem?**

No. The script is idempotent and uses `|| true` after each creation step, so it will continue past existing resources.

**Q: How do I reset the Keycloak database?**

```bash
docker compose stop ztf-keycloak ztf-keycloak-db
docker volume rm ztforensics_keycloak_db_data
docker compose up -d ztf-keycloak-db ztf-keycloak
bash scripts/setup_keycloak.sh
```
