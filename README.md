# OpenID4VP .NET Library

A comprehensive .NET implementation of the **OpenID for Verifiable Presentations 1.0** specification ([openid-4-verifiable-presentations-1_0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)).

## Overview

OpenID4VP enables Wallets to present Verifiable Credentials to Verifiers using a standardized, protocol-driven approach. This library provides .NET developers with:

- **Unified URI Builder** supporting all three OpenID4VP transport mechanisms:
  - Option A: Direct URL with encoded parameters (same-device)
  - Option B: Request Object as JWT value (same-device, protected)
  - Option C: Request Object by reference (cross-device, QR codes)
- **Builder Pattern API** for constructing compliant Authorization Requests
- **Scenario-Specific Validators** for same-device and cross-device flows
- **Response Parsing** with comprehensive error handling
- **DCQL Support** for Digital Credentials Query Language (Spec Section 6)
- **Type-Safe Models** representing OpenID4VP data structures
- **Result<T> Pattern** for elegant error accumulation and reporting

## Quick Start

### Option A: Direct URL (Same-Device Flow)

```csharp
using OpenID4VP.Builders;

// Build a full authorization request
var request = AuthorizationRequestBuilder.Create()
    .WithClientId("verifier-1")
    .WithNonce("cryptographically_random_nonce_value")
    .WithResponseType("vp_token")
    .WithResponseMode("query")  // redirect via query parameters
    .WithScope("openid")
    .Build();

if (request.IsSuccess)
{
    // Generate a URI with all parameters encoded
    var uriResult = AuthorizationRequestUriBuilder.Create(request.Value)
        .AsDirectUrl("https://wallet.example.com/auth");
    
    if (uriResult.IsSuccess)
    {
        // uriResult.Value: https://wallet.example.com/auth?client_id=...&nonce=...&response_type=...&response_mode=...
        RedirectToWallet(uriResult.Value);
    }
}
```

**When to Use:** Same-device flow where the wallet is on the same device as the verifier.
**What's Included:** All request parameters (client_id, nonce, response_type, response_mode, scope, etc.)
**Result:** Complete URI with all parameters URL-encoded in query string

---

### Option B: Request Object by Value (Same-Device with Protected Request)

```csharp
using OpenID4VP.Builders;

// Build request
var request = AuthorizationRequestBuilder.Create()
    .WithClientId("verifier-1")
    .WithNonce("cryptographically_random_nonce_value")
    .WithResponseType("vp_token")
    .WithScope("openid")
    .Build();

if (request.IsSuccess)
{
    // Sign the request (caller is responsible for signing/encryption)
    // This is a placeholder - implement your own JWT signing logic
    var jwt = SignAndEncryptRequest(request.Value);  
    
    // Generate URI with JWT embedded in 'request' parameter
    var uriResult = AuthorizationRequestUriBuilder.Create(request.Value)
        .AsRequestObjectByValue("https://wallet.example.com/auth", jwt);
    
    if (uriResult.IsSuccess)
    {
        // uriResult.Value: https://wallet.example.com/auth?request=eyJhbGciOiJSUzI1NiIs...
        RedirectToWallet(uriResult.Value);
    }
}
```

**When to Use:** Same-device flow with protected request (signed/encrypted JWT).
**What's Included:** Only the 'request' parameter containing the base64url-encoded JWT.
**Result:** Minimal URI with just the JWT-encoded request

---

### Option C: Request Object by Reference (Cross-Device QR Code)

```csharp
using OpenID4VP.Builders;

// Build a minimal request for cross-device
var request = AuthorizationRequestBuilder.Create()
    .WithClientId("verifier-app-1")
    .WithNonce("cryptographically_random_nonce_value")  // REQUIRED per spec
    .WithRequestUri("https://verifier.example.com/request/req-2024-001")
    .WithRequestUriMethod("post")  // optional: "get" (default) or "post"
    .WithState("optional_state_correlator")
    .Build();

if (request.IsSuccess)
{
    // Generate a minimal request URI suitable for QR code encoding
    var qrResult = AuthorizationRequestUriBuilder.Create(request.Value)
        .AsRequestObjectByReference("openid4vp://");
    
    if (qrResult.IsSuccess)
    {
        // qrResult.Value: openid4vp://?client_id=...&request_uri=...&nonce=...
        var qrCodeUri = qrResult.Value;
        GenerateQrCode(qrCodeUri);
    }
}
```

**When to Use:** Cross-device flow where wallet is on a different device (QR code scanning).
**What's Included:** Minimal request (client_id, request_uri, nonce, state, request_uri_method).
**Result:** Compact URI suitable for QR code encoding.

**How It Works:**
1. Wallet scans QR code → gets minimal request URI
2. Wallet fetches full authorization request from `request_uri` endpoint
3. Full request contains: response_mode, response_type, dcql_query, etc.
4. Wallet processes full request and returns response to response_uri

---

### Cross-Device QR Code Generation (Device-Switching Flow)

```csharp
using OpenID4VP.Builders;

// Generate a minimal request URI suitable for QR code encoding
var result = CrossDeviceRequestUriBuilder.Create()
    .WithClientId("verifier-app-1")
    .WithRequestUri("https://verifier.example.com/request/req-2024-001")
    .WithNonce("cryptographically_random_nonce_value")  // REQUIRED per spec
    .WithState("optional_state_correlator")
    .WithParameter("custom_param", "value")  // extensibility
    .Build("https://qr.verifier.example.com/auth");

if (result.IsSuccess)
{
    // result.Value is the complete, encoded URI ready for QR code generation
    var qrCodeUri = result.Value;
    GenerateQrCode(qrCodeUri);
}
else
{
    // Accumulate and report all validation errors
    foreach (var error in result.Errors)
        Console.WriteLine($"[{error.Code}] {error.Message}");
}
```

**What This Does:**
- Generates a minimal authorization request with only: `client_id`, `request_uri`, `nonce`, `state` (optional)
- Per OpenID4VP Spec Section 3.2, this minimal request is embedded in a QR code
- When scanned by the wallet, it resolves to the `request_uri` endpoint to fetch the full authorization request
- Supports custom parameters for extensibility via `.WithParameter()`

**Nonce Requirement:**
Per OpenID4VP Spec Section 5.2, the nonce is **REQUIRED** for every authorization request. The builder validates that:
- Nonce is provided
- Nonce contains only ASCII URL-safe characters (RFC 3986: A-Z, a-z, 0-9, `-`, `.`, `_`, `~`)

## Architecture

The library implements the OpenID4VP specification with clear separation of concerns:

- **Models** (`src/OpenID4VP/Models/`) - Type-safe data structures
- **Builders** (`src/OpenID4VP/Builders/`) - Fluent API for request construction
- **Validators** (`src/OpenID4VP/Validators/`) - Scenario-specific validation rules
- **DCQL** (`src/OpenID4VP.Dcql/`) - Digital Credentials Query Language support

## Spec Compliance

✅ **Supports All Three Transport Options (Section 5.4):**
- Option A: Direct URL with all parameters encoded as query string
- Option B: Request Object as JWT value in 'request' parameter  
- Option C: Request Object by reference via request_uri (cross-device QR)

✅ **Supports Multiple Flows:**
- Same-Device: User interacts directly with wallet on verifier's device
- Cross-Device: Wallet on different device (QR code, out-of-band)
- Request Object: Full request fetched from URI endpoint

✅ **Validation:**
- Nonce: ASCII URL-safe characters per RFC 3986 (ALWAYS REQUIRED per Section 5.2)
- Client ID: Optional prefix support (x509_san_dns, x509_san_uri, etc.)
- Response Mode: Scenario-specific enforcement (required for same-device/Option A, optional for cross-device)
- DCQL Queries: Digital Credentials Query Language per Spec Section 6
- State: Optional, must contain ASCII URL-safe characters if provided

✅ **Error Handling:**
- Accumulates all validation errors (not fail-fast)
- Result<T> pattern for elegant error reporting
- Clear error messages with specific violation details

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## References

- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)


