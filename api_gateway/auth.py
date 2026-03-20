from fastapi import Header, HTTPException


def get_current_subject(authorization: str | None = Header(default=None)) -> dict:
    """
    Temporary auth parser for development.
    Expected header format:
      Authorization: Bearer user:<username>;role:<role>

    Example:
      Bearer user:ahmed;role:employee
      Bearer user:admin;role:admin
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization.replace("Bearer ", "", 1).strip()

    # Dev-mode token parser
    # format: user:<u>;role:<r>
    try:
        parts = dict(item.split(":", 1) for item in token.split(";"))
        user = parts.get("user")
        role = parts.get("role", "employee")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format")

    if not user:
        raise HTTPException(status_code=401, detail="Token missing user")

    return {
        "sub": user,
        "role": role
    }