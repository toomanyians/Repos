import sys, time, json, base64, uuid, hashlib
from ctypes import *
from ctypes.util import find_library

identity_name = sys.argv[1]
tenant = sys.argv[2]
client = sys.argv[3]

# Load macOS frameworks
Security = CDLL(find_library("Security"))
CoreFoundation = CDLL(find_library("CoreFoundation"))

CFTypeRef = c_void_p
CFArrayRef = c_void_p

# CF helpers
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p
CoreFoundation.CFArrayCreate.argtypes = [CFTypeRef, POINTER(CFTypeRef), c_long, CFTypeRef]
CoreFoundation.CFArrayCreate.restype = CFArrayRef
CoreFoundation.CFStringGetCStringPtr.argtypes = [c_void_p, c_uint32]
CoreFoundation.CFStringGetCStringPtr.restype = c_char_p
CoreFoundation.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
CoreFoundation.CFStringGetCString.restype = c_bool
CoreFoundation.CFDataCreate.argtypes = [c_void_p,POINTER(c_ubyte),c_long]
CoreFoundation.CFDataCreate.restype = c_void_p

def CFStringToStr(cf_str):
    if not cf_str:
        return ""
    c_ptr = CoreFoundation.CFStringGetCStringPtr(cf_str, 0)
    if c_ptr:
        return c_ptr.decode()
    buf = create_string_buffer(4096)
    CoreFoundation.CFStringGetCString(cf_str, buf, 4096, 0)
    return buf.value.decode()

# Security API signatures
Security.SecCertificateCopyData.argtypes = [c_void_p]
Security.SecCertificateCopyData.restype = c_void_p
Security.SecKeychainOpen.argtypes = [c_char_p, POINTER(c_void_p)]
Security.SecKeychainOpen.restype = c_int32
Security.SecIdentitySearchCreate.argtypes = [CFArrayRef, c_uint32, POINTER(c_void_p)]
Security.SecIdentitySearchCreate.restype = c_int32
Security.SecIdentitySearchCopyNext.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentitySearchCopyNext.restype = c_int32
Security.SecIdentityCopyCertificate.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyCertificate.restype = c_int32
Security.SecCertificateCopySubjectSummary.argtypes = [c_void_p]
Security.SecCertificateCopySubjectSummary.restype = c_void_p
Security.SecIdentityCopyPrivateKey.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyPrivateKey.restype = c_int32
Security.SecKeyCreateSignature.argtypes = [c_void_p,c_void_p,c_void_p,POINTER(c_void_p)]
Security.SecKeyCreateSignature.restype = c_void_p

# Load System keychain
system_keychain = c_void_p()
status = Security.SecKeychainOpen(b"/Library/Keychains/System.keychain",byref(system_keychain))
if status != 0:
    print("ERROR: cannot open System keychain")
    sys.exit(1)

# Build CFArrayRef containing ONLY the System keychain
values = (CFTypeRef * 1)(system_keychain.value)
keychain_array = CoreFoundation.CFArrayCreate(None, values, 1, None)

# Create identity search
search = c_void_p()
status = Security.SecIdentitySearchCreate(keychain_array,0,byref(search))
if status != 0 or not search.value:
    print("ERROR: failed to create identity search")
    sys.exit(1)

# Find identity by Common Name
identity = c_void_p()
cert = c_void_p()

while True:
    status = Security.SecIdentitySearchCopyNext(search, byref(identity))
    if status != 0:
        break

    Security.SecIdentityCopyCertificate(identity, byref(cert))
    summary = Security.SecCertificateCopySubjectSummary(cert)
    name = CFStringToStr(summary)

    if identity_name.lower() in name.lower():
        break

if not identity.value:
    print("ERROR: identity not found in System keychain")
    sys.exit(1)

# Extract private key
private_key = c_void_p()
status = Security.SecIdentityCopyPrivateKey(identity, byref(private_key))
if status != 0 or not private_key.value:
    print("ERROR: cannot extract private key")
    sys.exit(1)
    
print("SecIdentityCopyPrivateKey:", status)
print("Private key:", hex(private_key.value) if private_key.value else None)

# Build JWT header + payload
# Get DER certificate bytes
cert_data = Security.SecCertificateCopyData(cert)
length = CoreFoundation.CFDataGetLength(cert_data)
ptr = CoreFoundation.CFDataGetBytePtr(cert_data)
der_bytes = string_at(ptr, length)

# SHA-1 thumbprint
thumbprint = hashlib.sha1(der_bytes).digest()

# Base64URL encode (no padding)
x5t = base64.urlsafe_b64encode(thumbprint).rstrip(b"=").decode()

header = {
    "alg": "RS256",
    "typ": "JWT",
    "x5t": x5t
}
header_json = json.dumps(
    header,
    separators=(",", ":"),
    sort_keys=False
).encode()

now = int(time.time())
exp = now + 600
jti = str(uuid.uuid4())

payload = {
    "aud": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
    "iss": client_id,
    "sub": client_id,
    "jti": jti,
    "iat": now,
    "nbf": now,
    "exp": exp
}
payload_json = json.dumps(
    payload,
    separators=(",", ":"),
    sort_keys=False
).encode()

def b64url(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

header_b64 = b64url(header_json)
payload_b64 = b64url(payload_json)
signing_input = f"{header_b64}.{payload_b64}".encode()
buffer = (c_ubyte * len(signing_input)).from_buffer_copy(signing_input)
cf_signing_input = CoreFoundation.CFDataCreate(None,buffer,len(signing_input))

# Sign using SecKeyCreateSignature (RSASSA-PKCS1v1.5 SHA256)
kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 = c_void_p.in_dll(Security, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")

error = c_void_p()
signature = Security.SecKeyCreateSignature(
    private_key,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    cf_signing_input,
    byref(error)
)

if not signature:
    print("Signing failed")
    sys.exit(1)

# Extract raw bytes from CFDataRef
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p

length = CoreFoundation.CFDataGetLength(signature)
ptr = CoreFoundation.CFDataGetBytePtr(signature)
raw_sig = string_at(ptr, length)

jwt = f"{header_b64}.{payload_b64}.{b64url(raw_sig)}"
print(jwt)