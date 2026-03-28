# Troubleshooting Setup Issues

This guide covers common problems encountered when setting up ZTForensics
and their solutions.

---

## Keycloak Connection Fails

**Symptom:** `KEYCLOAK_SERVER_URL/health/ready` returns an error or the API Gateway logs show JWT validation failures.

**Possible causes & solutions:**

1. **Keycloak is still starting up.**
   Keycloak can take 60–90 s on first boot.
   ```bash
   docker compose logs -f ztf-keycloak | grep "started in"
   ```
   Wait for `Keycloak X.Y.Z on JVM started in N.Ns.` message.

2. **Wrong `KEYCLOAK_SERVER_URL` inside Docker.**
   From inside Docker containers, use the internal hostname `ztf-keycloak`,
   not `localhost`. Ensure:
   ```env
   KEYCLOAK_SERVER_URL=http://ztf-keycloak:8080   # for containers
   KEYCLOAK_SERVER_URL=http://localhost:8080       # for scripts on host
   ```

3. **Realm or client does not exist.**
   Re-run the setup script:
   ```bash
   bash scripts/setup_keycloak.sh
   ```

4. **Wrong client secret.**
   Retrieve the current secret from the Keycloak Admin UI:
   **Clients → api-gateway → Credentials → Client secret**
   and update `KEYCLOAK_CLIENT_SECRET` in `.env`, then:
   ```bash
   docker compose restart ztf-api
   ```

---

## Database Connection Fails

**Symptom:** API Gateway exits with `could not connect to server` or `FATAL: password authentication failed`.

**Checks:**

```bash
docker compose ps ztf-postgres                     # must be healthy
docker compose logs ztf-postgres | tail -20
docker exec ztf-postgres pg_isready -U ztf -d ztfdb
```

**Solutions:**

- If the container is not healthy, check for port conflicts:
  ```bash
  lsof -i :5432      # something else may be using the port
  ```
- If credentials are wrong, verify `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` in `docker-compose.yml` match `DATABASE_URL` in `.env`.
- Destroy and recreate the volume if the database is corrupted:
  ```bash
  docker compose down
  docker volume rm ztforensics_postgres_data
  docker compose up -d
  ```

---

## OPA Service Unavailable

**Symptom:** API Gateway logs `OPA unreachable; defaulting to allow`.

**Checks:**

```bash
docker compose ps ztf-opa
curl http://localhost:8181/health
```

**Solutions:**

- Check that the OPA container started:
  ```bash
  docker compose logs ztf-opa
  ```
- Verify that the policy directory `./opa/policies/` contains `.rego` files and the volume mount in `docker-compose.yml` is correct.
- Check that the policy compiles without errors:
  ```bash
  docker exec ztf-opa opa check /policies
  ```

---

## Port Already in Use

**Symptom:** `Error starting userland proxy: listen tcp 0.0.0.0:8080: bind: address already in use`

**Find what is using the port:**

```bash
lsof -i :8080      # macOS / Linux
netstat -tulpn | grep 8080   # Linux
```

**Solutions:**

- Stop the conflicting process, or
- Override the port in your `.env`:
  ```env
  API_GATEWAY_PORT=8001
  DASHBOARD_PORT=5001
  ```
  Then update `docker-compose.yml` port mappings accordingly.

---

## Certificate Issues (TLS)

**Symptom:** `SSL certificate verify failed` or `unable to get local issuer certificate`.

**Solutions:**

- In development, disable TLS verification by setting `KC_HOSTNAME_STRICT_HTTPS=false` in Keycloak and using `http://` URLs.
- For production, ensure your certificate chain is complete and trusted.
- If using a self-signed CA, add it to the container trust store:
  ```dockerfile
  COPY my-ca.crt /usr/local/share/ca-certificates/
  RUN update-ca-certificates
  ```

---

## Permission Denied Errors

**Symptom:** Docker volume or bind mount operations fail with `Permission denied`.

**Solutions:**

- Check ownership of `./opa/policies/`:
  ```bash
  ls -la opa/policies/
  ```
- Fix ownership:
  ```bash
  chmod -R 755 opa/policies/
  ```
- On Linux with SELinux enabled, add the `:z` volume option:
  ```yaml
  volumes:
    - ./opa/policies:/policies:ro,z
  ```

---

## Network Issues

**Symptom:** Containers cannot reach each other by hostname.

**Checks:**

```bash
docker network ls | grep ztf
docker network inspect ztforensics_ztf-net
```

**Solutions:**

- Ensure all services are on the same Docker network (`ztf-net`).
- Recreate the network:
  ```bash
  docker compose down
  docker network rm ztforensics_ztf-net 2>/dev/null || true
  docker compose up -d
  ```

---

## Resource Constraints

**Symptom:** Services crash, restart loop, or OOM-killed.

**Debug:**

```bash
docker stats                  # live CPU / memory usage
docker compose logs ztf-api   # look for OOM messages
```

**Solutions:**

- Ensure at least **4 GB RAM** is allocated to Docker (Docker Desktop → Settings → Resources).
- Reduce `DATABASE_POOL_SIZE` to free up database connections.
- Stop unused services:
  ```bash
  docker compose stop ztf-dashboard
  ```

---

## General Debug Commands

```bash
# View all service logs
docker compose logs

# Stream logs from a specific service
docker compose logs -f ztf-api

# Check container resource usage
docker stats --no-stream

# Execute a shell inside a container
docker exec -it ztf-api /bin/sh

# Rebuild images after code changes
docker compose build --no-cache ztf-api
docker compose up -d ztf-api

# Full reset (removes all data)
docker compose down -v
docker compose up -d
```

---

## Still Stuck?

1. Run the health check script:
   ```bash
   bash scripts/health_check.sh
   ```
2. Run the environment validation:
   ```bash
   python scripts/validate_env.py
   ```
3. Run the pre-start checks:
   ```bash
   python prestart_checks.py
   ```
4. Check the [SETUP.md](SETUP.md) guide and [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md).
