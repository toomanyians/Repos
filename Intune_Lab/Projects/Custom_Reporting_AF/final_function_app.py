import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import azure.functions as func
import requests

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

TRUSTED_ISSUER_CN = os.getenv("TRUSTED_ISSUER_CN","IntuneLab_ROOT_CA2")

KEYVAULT_NAME = os.getenv("KEYVAULT_NAME","kv-intune-ianbaxter")

CA_SECRET_NAME = os.getenv("CA_SECRET_NAME","IntuneLab-ROOT-CA2")

LOGS_INGESTION_ENDPOINT = os.getenv("LOGS_INGESTION_ENDPOINT")
DCR_IMMUTABLE_ID = os.getenv("DCR_IMMUTABLE_ID")
DCR_STREAM_NAME = os.getenv("DCR_STREAM_NAME")

LOGS_API_VERSION = "2023-01-01"

# Maximum amount of upstream response text we'll put into logs/responses.
MAX_RESPONSE_TEXT = 4000

# ----------------------------------------------------------------------
# Cached Azure clients / certificates
# ----------------------------------------------------------------------

_credential = DefaultAzureCredential()
_ca_cert = None

# ----------------------------------------------------------------------
# BEGIN FUNCTIONS
# ----------------------------------------------------------------------

# _get_ca_cert() - Returns the PEM contents of the CA in a key vault
#    secret as an X.509 certificate. If the certificate has already
#    been retrieved, return the cached copy.
def _get_ca_cert() -> x509.Certificate:
    global _ca_cert
    # Return the cached certificate if it exists
    if _ca_cert is not None:
        return _ca_cert
    # Form the key vault url
    kv_url = f"https://{KEYVAULT_NAME}.vault.azure.net"
    # Create the client object and retrieve the secret contents
    client = SecretClient(vault_url=kv_url,credential=_credential)
    secret = client.get_secret(CA_SECRET_NAME)
    # If not value was returned, error out
    if not secret.value:
        raise RuntimeError(f"Key Vault secret '{CA_SECRET_NAME}' was empty")
    # Ensure the PEM contents are converted to utf-8 encoding
    pem_bytes = secret.value.encode("utf-8")
    # Convert the PEM to an X.509 certificate
    _ca_cert = x509.load_pem_x509_certificate(pem_bytes,default_backend())
    # If we got to here, log the success
    logging.info(
        "Loaded trusted CA certificate from Key Vault. "
        "subject=%s",
        _ca_cert.subject.rfc4514_string()
    )
    # Return the X.509 certificate
    return _ca_cert

# ----------------------------------------------------------------------
# HTTP response helper
# ----------------------------------------------------------------------

# _json_response() - builds an HTTP response with a JSON payload for the
#    body with a specified http response code
def _json_response(body, status_code):
    return func.HttpResponse(
        json.dumps(body,default=str),
        status_code=status_code,
        mimetype="application/json"
    )

# ----------------------------------------------------------------------
# Certificate helpers
# ----------------------------------------------------------------------

# _get_attr() - Gets the certificate property value by name and Object
#    Identifier.
def _get_attr(name, oid):
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except (IndexError, AttributeError):
        return None

# _certificate_time() - Gets a time value from the certificate in the
#    newer UTC format, or legacy local time format if UTC is not available.
def _certificate_time(cert, attribute_name, legacy_attribute_name):
    """
    Cryptography newer releases provide *_utc attributes.
    Fall back to the older naive datetime attributes if necessary.
    """
    # Attempt to get the time value in new UTC format
    value = getattr(cert, attribute_name, None)
    # If found, return it
    if value is not None:
        return value
    # If not, get the legacy version date value
    value = getattr(cert, legacy_attribute_name)
    # If it was found, convert it to UTC if it's local
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    # Return what we found
    return value

# _validate_client_certificate() - Performs certificate validation of
#    the mTLS client certificate against the Issuer CA certificate
def _validate_client_certificate(cert: x509.Certificate) -> dict:
    """
    Returns certificate metadata when validation succeeds.
    """
    # Get the Issuer CA cert from cache or key vault
    ca_cert = _get_ca_cert()
    # Verify that the client cert issuer matches the trusted CA subject
    if cert.issuer != ca_cert.subject:
        raise ValueError("Certificate issuer does not match trusted CA subject")
    # Get the Issuer CA cert Common name.
    issuer_cn = _get_attr(cert.issuer,x509.NameOID.COMMON_NAME)
    # Check that it matches the CA name in our environment variable
    if issuer_cn != TRUSTED_ISSUER_CN:
        raise ValueError(
            f"Certificate issuer CN '{issuer_cn}' "
            f"does not match trusted issuer '{TRUSTED_ISSUER_CN}'"
        )
    # Get the CA Public Key
    ca_public_key = ca_cert.public_key()
    # Verify the client certificate signature against the CA Publick Key
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    # Get the current time in UTC
    now = datetime.now(timezone.utc)
    # Get the Valid_From of the client certificate in UTC
    valid_from = _certificate_time(cert,"not_valid_before_utc","not_valid_before")
    # Get the Valid_To of the client certificate in UTC
    valid_to = _certificate_time(cert,"not_valid_after_utc","not_valid_after")
    # Check validity period
    if now < valid_from:
        raise ValueError("Client certificate is not yet valid")
    if now > valid_to:
        raise ValueError("Client certificate has expired")
    # Get the client certificate Common Name
    subject_cn = _get_attr(cert.subject,x509.NameOID.COMMON_NAME)
    # Get the client certificate Publik Key
    public_key = cert.public_key()
    # Return useful metadata
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "serial_number": str(cert.serial_number),
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "public_key_type": type(public_key).__name__,
        "public_key_size": getattr(public_key, "key_size", None),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }

# ----------------------------------------------------------------------
# JSON validation
# ----------------------------------------------------------------------

# _validate_payload(payload) - Performs basic validation before sending the 
#     payload to Azure Monitor.
def _validate_payload(payload):
    """
    DCR-specific field validation can be added here once the exact
    streamDeclaration schema is known.
    """
    # Allow the caller to submit either:
    #   { ... } or [ { ... }, { ... } ]
    # Azure Monitor ultimately requires an array.
    #
    # Convert the JSON submission to a common format and verify
    # it is a valid JSON format
    if isinstance(payload, dict):
        records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("JSON body must contain an object or an array of objects")
    # Make sure at least one valid record has been submitted
    if len(records) == 0:
        raise ValueError("JSON array must contain at least one record")
    # Check each record in the submission
    for index, record in enumerate(records):
        # Verify it is a Key->Value pair
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} must be a JSON object")
        # Verify it is not empty
        if not record:
            raise ValueError(f"Record {index} cannot be empty")
    # Return the validated structure back to the caller
    return records

# ----------------------------------------------------------------------
# Send records to Azure Monitor
# ----------------------------------------------------------------------

# _send_to_azure_monitor() - Send the validated records to the Logs Ingestion API.
def _send_to_azure_monitor(records, client_request_id):
    """
    Returns the raw requests.Response so the Azure Monitor status code
    can be propagated back to the original caller.
    """
    # Check that the Environment Variables we need to build the Log Ingestion
    # API 2.0 endpoint URL exist
    if not LOGS_INGESTION_ENDPOINT:
        raise RuntimeError("LOGS_INGESTION_ENDPOINT application setting is missing")
    if not DCR_IMMUTABLE_ID:
        raise RuntimeError("DCR_IMMUTABLE_ID application setting is missing")
    if not DCR_STREAM_NAME:
        raise RuntimeError("DCR_STREAM_NAME application setting is missing")
    # Strip off any trailing slash for the DCE URL
    endpoint = LOGS_INGESTION_ENDPOINT.rstrip("/")
    # Build the endpoint URL from its components
    ingestion_url = (
        f"{endpoint}"
        f"/dataCollectionRules/{DCR_IMMUTABLE_ID}"
        f"/streams/{DCR_STREAM_NAME}"
        f"?api-version={LOGS_API_VERSION}"
    )
    # Managed identity / DefaultAzureCredential token for Azure Monitor.
    token = _credential.get_token("https://monitor.azure.com/.default")
    # Build the headers for the POST
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json",
        "x-ms-client-request-id": client_request_id,
    }
    # Log the info we use for the POST
    logging.info(
        "Submitting %d record(s) to Azure Monitor. "
        "request_id=%s dcr=%s stream=%s",
        len(records),
        client_request_id,
        DCR_IMMUTABLE_ID,
        DCR_STREAM_NAME,
    )
    # Send the data to the API endpoint
    response = requests.post(
        ingestion_url,
        headers=headers,
        json=records,
        timeout=(10, 30),
    )
    # Return the POST response
    return response

# ----------------------------------------------------------------------
# Azure Function
# ----------------------------------------------------------------------

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="datacollect")
@app.route(
    route="datacollect",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS
)
def datacollect(req: func.HttpRequest) -> func.HttpResponse:
    # Create a unique id so we can identify this pose in the logs
    request_id = str(uuid.uuid4())
    # Log that the Azure function has received a JSON submission
    logging.info("Data collection request received. request_id=%s",request_id)
    # Get the client certificate from the header
    cert_b64 = req.headers.get("X-ARR-ClientCert")
    # If there is no client certificate, log it and exit with the response
    if not cert_b64:
        logging.warning("Client certificate missing. request_id=%s",request_id)
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "No client certificate"
            },
            401
        )
    try:
        # Validate that the certificate is Base64
        cert_der = base64.b64decode(cert_b64,validate=True)
        # Convert from the Base64 value (Public Key) to an X.509 certificate
        cert = x509.load_der_x509_certificate(cert_der,default_backend())
    except Exception as exc:
        # Not a valid certificate, log it
        logging.warning(
            "Invalid client certificate. "
            "request_id=%s error=%s",
            request_id,
            exc
        )
        # Exit with the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Invalid client certificate"
            },
            400
        )

    try:
        # Perform full client certificate validation
        cert_info = _validate_client_certificate(cert)
    except Exception as exc:
        # Validation failed, log it
        logging.warning(
            "Client certificate validation failed. "
            "request_id=%s error=%s",
            request_id,
            exc
        )
        # Exit and send back the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Client certificate validation failed"
            },
            403
        )
    # Certificate validation passed, log it
    logging.info(
        "Client certificate validated. "
        "request_id=%s subject_cn=%s fingerprint=%s",
        request_id,
        cert_info["subject_cn"],
        cert_info["fingerprint_sha256"],
    )
    # Get the Mime content type from the submission header
    content_type = req.headers.get("Content-Type","").lower()
    # If it's not "application/json"
    if "application/json" not in content_type:
        # Log it
        logging.warning(
            "Invalid content type. "
            "request_id=%s content_type=%s",
            request_id,
            content_type
        )
        # Exit and send the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Content-Type must be application/json"
            },
            415
        )
    # Parse the JSON
    try:
        payload = req.get_json()
    # If it failed to parse properly
    except ValueError as exc:
        # Log it
        logging.warning(
            "Invalid JSON received. "
            "request_id=%s error=%s",
            request_id,
            exc
        )
        # Exit and send the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Request body contains invalid JSON"
            },
            400
        )
    # We have a valid JSON, perform the full validation
    try:
        records = _validate_payload(payload)
    # If the full validation failed
    except ValueError as exc:
        # Log it
        logging.warning(
            "JSON validation failed. "
            "request_id=%s error=%s",
            request_id,
            exc
        )
        # Exit and send back the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": str(exc)
            },
            400
        )
    # Send the validated submission to the DCE/DCR endpoint
    try:
        response = _send_to_azure_monitor(records,request_id)
    # If it failed to send
    except requests.RequestException as exc:
        # Log it
        logging.exception("Unable to contact Azure Monitor. request_id=%s",request_id)
        # Exit and send back the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Unable to contact Azure Monitor",
                "detail": str(exc)
            },
            502
        )
    # If it sent and responded back with an error
    except Exception as exc:
        # Log it
        logging.exception(
            "Internal ingestion error. request_id=%s",
            request_id
        )
        # Exit and send back the response
        return _json_response(
            {
                "success": False,
                "request_id": request_id,
                "error": "Internal ingestion error",
                "detail": str(exc)
            },
            500
        )
    # Get the status_code returned from the DCE/CDR data submission
    upstream_status = response.status_code
    # Get any textual response, or a blank string
    upstream_body = response.text or ""
    # If the length of the text response exceeds 4000 characters, truncate it
    if len(upstream_body) > MAX_RESPONSE_TEXT:
        upstream_body = upstream_body[:MAX_RESPONSE_TEXT]
    # Get the Azure request ID
    azure_request_id = (
        response.headers.get("x-ms-request-id")
        or response.headers.get("request-id")
    )
    # Calculate success as any status_code between 200 and 299
    success = 200 <= upstream_status < 300
    # Log the DCE/DCR submission status
    logging.info(
        "Azure Monitor ingestion completed. "
        "request_id=%s "
        "azure_request_id=%s "
        "subject_cn=%s "
        "records=%d "
        "status_code=%d "
        "success=%s "
        "response=%s",
        request_id,
        azure_request_id,
        cert_info["subject_cn"],
        len(records),
        upstream_status,
        success,
        upstream_body,
    )
    # Create a response JSON to send back to the caller
    result = {
        "success": success,
        "request_id": request_id,
        "azure_request_id": azure_request_id,
        "status_code": upstream_status,
        "records_submitted": len(records),
        "certificate": {
            "subject_cn": cert_info["subject_cn"],
            "fingerprint_sha256": cert_info["fingerprint_sha256"],
        }
    }
    # If we got a text response from the DCE/DCR, include it in the JSON response
    if upstream_body:
        try:
            result["ingestion_response"] = response.json()
        except ValueError:
            result["ingestion_response"] = upstream_body
    # Return the response to the caller
    return _json_response(result,upstream_status)
