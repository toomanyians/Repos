import logging
import base64

import azure.functions as func
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

TRUSTED_ISSUER_CN = "<ROOT CA CN>"
KEYVAULT_NAME = "<KEYVAULT NAME>"
CA_SECRET_NAME = "<KEYVAULT SECRET NAME>"

# Cache CA cert in memory so we don’t hit Key Vault on every request
_ca_cert = None


def _get_ca_cert() -> x509.Certificate:
    global _ca_cert
    if _ca_cert is not None:
        return _ca_cert

    kv_url = f"https://{KEYVAULT_NAME}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_url, credential=credential)

    secret = client.get_secret(CA_SECRET_NAME)
    pem = secret.value
    pem_bytes = pem.encode("utf-8")

    _ca_cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    return _ca_cert


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


@app.function_name(name="datacollect")
@app.route(
    route="datacollect",
    auth_level=func.AuthLevel.ANONYMOUS
)
def datacollect(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("mTLS request received")

    cert_b64 = req.headers.get("X-ARR-ClientCert")
    if not cert_b64:
        return func.HttpResponse("No client certificate", status_code=401)

    try:
        cert_der = base64.b64decode(cert_b64)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception as e:
        logging.error(f"Certificate decode error: {e}")
        return func.HttpResponse("Invalid certificate", status_code=400)

    # -----------------------------
    # 1) Trust chain / signature validation using CA from Key Vault
    # -----------------------------
    try:
        ca_cert = _get_ca_cert()
        ca_public_key = ca_cert.public_key()

        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        logging.error(f"Chain validation failed: {e}")
        return func.HttpResponse("Certificate not signed by trusted CA", status_code=403)

    # -----------------------------
    # 2) Issuer pinning (CN must match expected CA)
    # -----------------------------
    issuer_cn = _get_attr(cert.issuer, x509.NameOID.COMMON_NAME)
    if issuer_cn != TRUSTED_ISSUER_CN:
        logging.warning(f"Issuer mismatch: {issuer_cn} != {TRUSTED_ISSUER_CN}")
        return func.HttpResponse("Untrusted certificate issuer", status_code=403)

    # -----------------------------
    # SUBJECT / BASIC METADATA
    # -----------------------------
    subject = cert.subject
    subject_cn = _get_attr(subject, x509.NameOID.COMMON_NAME)

    serial_number = cert.serial_number
    valid_from = cert.not_valid_before
    valid_to = cert.not_valid_after

    public_key = cert.public_key()
    public_key_type = type(public_key).__name__
    public_key_size = getattr(public_key, "key_size", None)

    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    result = {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "serial_number": serial_number,
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "public_key_type": public_key_type,
        "public_key_size": public_key_size,
        "fingerprint_sha256": fingerprint_sha256,
    }

    return func.HttpResponse(str(result), status_code=200)


def _get_attr(name, oid):
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except Exception:
        return None
