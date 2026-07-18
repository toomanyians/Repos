import sys, time, json, base64, uuid, hashlib
from datetime import datetime, timedelta, timezone
from ctypes import *
from ctypes.util import find_library
# Load command line arguments
identity_name = sys.argv[1]
tenant_id = sys.argv[2]
client_id = sys.argv[3]
# Load macOS frameworks
Security = CDLL(find_library("Security"))
CoreFoundation = CDLL(find_library("CoreFoundation"))
# Type definitions
# CoreFoundation opaque types
CFTypeRef       = c_void_p
CFDictionaryRef = c_void_p
CFArrayRef      = c_void_p
CFStringRef     = c_void_p
CFDateRef       = c_void_p
CFNumberRef     = c_void_p
# CoreFoundation scalar types
CFTypeID = c_ulong
CFIndex  = c_long
# CF type identification
CoreFoundation.CFGetTypeID.argtypes = [CFTypeRef]
CoreFoundation.CFGetTypeID.restype = CFTypeID
CoreFoundation.CFDataCreate.argtypes = [c_void_p,POINTER(c_ubyte),c_long]
CoreFoundation.CFDataCreate.restype = c_void_p
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p
CoreFoundation.CFDateGetTypeID.argtypes = []
CoreFoundation.CFDateGetTypeID.restype = CFTypeID
CoreFoundation.CFArrayCreate.argtypes = [CFTypeRef, POINTER(CFTypeRef), c_long, CFTypeRef]
CoreFoundation.CFArrayCreate.restype = CFArrayRef
CoreFoundation.CFArrayGetTypeID.argtypes = []
CoreFoundation.CFArrayGetTypeID.restype = CFTypeID
CoreFoundation.CFArrayGetCount.argtypes = [CFArrayRef]
CoreFoundation.CFArrayGetCount.restype = c_long
CoreFoundation.CFArrayGetValueAtIndex.argtypes = [CFArrayRef, c_long]
CoreFoundation.CFArrayGetValueAtIndex.restype = CFTypeRef
CoreFoundation.CFStringGetCStringPtr.argtypes = [c_void_p, c_uint32]
CoreFoundation.CFStringGetCStringPtr.restype = c_char_p
CoreFoundation.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
CoreFoundation.CFStringGetCString.restype = c_bool
CoreFoundation.CFStringGetTypeID.argtypes = []
CoreFoundation.CFStringGetTypeID.restype = CFTypeID
CoreFoundation.CFDateGetAbsoluteTime.argtypes = [c_void_p]
CoreFoundation.CFDateGetAbsoluteTime.restype = c_double
CoreFoundation.CFDictionaryGetValue.argtypes = [CFDictionaryRef, CFTypeRef]
CoreFoundation.CFDictionaryGetValue.restype = CFTypeRef
CoreFoundation.CFDictionaryContainsKey.argtypes = [CFDictionaryRef, CFTypeRef]
CoreFoundation.CFDictionaryContainsKey.restype = c_bool
CoreFoundation.CFDictionaryGetTypeID.argtypes = []
CoreFoundation.CFDictionaryGetTypeID.restype = CFTypeID
CoreFoundation.CFDictionaryGetCount.argtypes = [CFDictionaryRef]
CoreFoundation.CFDictionaryGetCount.restype = c_long
CoreFoundation.CFDictionaryGetKeysAndValues.argtypes = [CFDictionaryRef,POINTER(CFTypeRef),POINTER(CFTypeRef)]
CoreFoundation.CFDictionaryGetKeysAndValues.restype = None
CoreFoundation.CFNumberGetValue.argtypes = [CFNumberRef,c_int,c_void_p]
CoreFoundation.CFNumberGetValue.restype = c_bool
CoreFoundation.CFNumberGetValue.argtypes = [CFTypeRef,c_int,c_void_p]
CoreFoundation.CFNumberGetValue.restype = c_bool
CoreFoundation.CFNumberGetTypeID.argtypes = []
CoreFoundation.CFNumberGetTypeID.restype = CFTypeID
# Type Conversion
def CFStringToStr(cf_str):
    if not cf_str:
        return ""
    c_ptr = CoreFoundation.CFStringGetCStringPtr(cf_str, 0)
    if c_ptr:
        return c_ptr.decode()
    buf = create_string_buffer(4096)
    CoreFoundation.CFStringGetCString(cf_str, buf, 4096, 0)
    return buf.value.decode()
def CFDictionaryToDict(cf_dict):
    def convert(obj):
        if not obj:
            return None
        tid = CoreFoundation.CFGetTypeID(obj)
        if tid == CoreFoundation.CFDateGetTypeID():
            return CFDateToDateTime(obj)        
        if tid == CoreFoundation.CFStringGetTypeID():
            return CFStringToStr(obj)
        if tid == CoreFoundation.CFNumberGetTypeID():
            return CFNumberToFloat(obj)
        if tid == CoreFoundation.CFArrayGetTypeID():
            count = CoreFoundation.CFArrayGetCount(obj)
            return [
                convert(CoreFoundation.CFArrayGetValueAtIndex(obj, i))
                for i in range(count)
            ]
        if tid == CoreFoundation.CFDictionaryGetTypeID():
            count = CoreFoundation.CFDictionaryGetCount(obj)
            keys = (CFTypeRef * count)()
            values = (CFTypeRef * count)()
            CoreFoundation.CFDictionaryGetKeysAndValues(
                obj,
                keys,
                values
            )
            d = {}
            for i in range(count):
                d[convert(keys[i])] = convert(values[i])
            return d
        if tid == CoreFoundation.CFNumberGetTypeID():
            return CFNumberToFloat(obj)
        return obj
    return convert(cf_dict)
def CFNumberToFloat(cf_number):
    value = c_double()
    # kCFNumberDoubleType = 13
    if CoreFoundation.CFNumberGetValue(cf_number,13,byref(value)):
        return value.value
    return None
def CFDateToDateTime(cf_date):
    """
    Convert a CFDateRef to a timezone-aware UTC datetime.
    CFDate epoch: 2001-01-01 00:00:00 UTC
    """
    if not cf_date:
        return None
    # Seconds since 2001-01-01 00:00:00 UTC
    abs_time = CoreFoundation.CFDateGetAbsoluteTime(cf_date)
    apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
    return apple_epoch + timedelta(seconds=abs_time)    
# Security API signatures
Security.SecCertificateCopyValues.argtypes = [c_void_p,c_void_p,POINTER(c_void_p)]
Security.SecCertificateCopyValues.restype = c_void_p
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
status = Security.SecIdentitySearchCreate(keychain_array, 0, byref(search))
if status != 0 or not search.value:
    print("ERROR: failed to create identity search")
    sys.exit(1)
# Find identity by Common Name with private key
identity = c_void_p()
cert = c_void_p()
# Keep looping till we can't find it, or one is found
while True:
    identity = c_void_p()
    status = Security.SecIdentitySearchCopyNext(search,byref(identity))
    if status != 0:
        break
    cert = c_void_p()
    status = Security.SecIdentityCopyCertificate(identity,byref(cert))
    if status != 0 or not cert.value:
        continue
    # Get the certificate name
    summary = Security.SecCertificateCopySubjectSummary(cert)
    name = CFStringToStr(summary)
    # Partial name match
    if identity_name.lower() not in name.lower():
        continue
    # Ask macOS for certificate fields
    error = c_void_p()
    values = Security.SecCertificateCopyValues(cert,None,byref(error))
    if not values:
        print("SecCertificateCopyValues failed")
        if error.value:
            print("CFError:", hex(error.value))

    # Convert CFDictionaryRef → Python dict
    values_dict = CFDictionaryToDict(values)
    # Extract NotBefore / NotAfter
    APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
    not_before_seconds = values_dict["2.16.840.1.113741.2.1.1.1.6"]["value"]
    not_after_seconds = values_dict["2.16.840.1.113741.2.1.1.1.7"]["value"]
    not_before = APPLE_EPOCH + timedelta(seconds=not_before_seconds)
    not_after = APPLE_EPOCH + timedelta(seconds=not_after_seconds)
    now = datetime.now(timezone.utc)
    # Check NotBefore and NotAfter to make sure it isn't expired
    if now < not_before or now > not_after:
        continue
    # Verify a private key exists
    private_key_test = c_void_p()
    status = Security.SecIdentityCopyPrivateKey(identity,byref(private_key_test))
    if status != 0 or not private_key_test.value:
        continue
    # Found matching identity with private key
    break
if not identity.value:
    print("ERROR: identity not found in System keychain")
    sys.exit(1)
# Extract private key
private_key = c_void_p()
status = Security.SecIdentityCopyPrivateKey(identity,byref(private_key))
if status != 0 or not private_key.value:
    print("ERROR: cannot extract private key")
    sys.exit(1)
#
#print("SecIdentityCopyPrivateKey:", status)
#print("Private key:", hex(private_key.value))
#
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
# Build the JWT header
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
# Build the JWT payload
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
# Returns Base64 encoded string
def b64url(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
#
header_b64 = b64url(header_json)
payload_b64 = b64url(payload_json)
signing_input = f"{header_b64}.{payload_b64}".encode()
buffer = (c_ubyte * len(signing_input)).from_buffer_copy(signing_input)
cf_signing_input = CoreFoundation.CFDataCreate(None,buffer,len(signing_input))
# Sign using SecKeyCreateSignature (RSASSA-PKCS1v1.5 SHA256)
kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 = c_void_p.in_dll(Security, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")
error = c_void_p()
signature = Security.SecKeyCreateSignature(private_key,kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,cf_signing_input,byref(error))
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