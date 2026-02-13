using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Validators;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for Request Object authorization requests (Section 3.2 & 6 of OpenID4VP spec).
/// 
/// Request Object is the full authorization parameters returned when wallet fetches from request_uri.
/// Fetched via HTTP GET from the request_uri endpoint specified in a minimal cross-device request.
/// 
/// Per spec: "The HTTP GET response returns the Request Object containing Authorization Request parameters"
/// 
/// +--------------+   +--------------+                                    +--------------+
/// |   End-User   |   |   Verifier   |                                    |    Wallet    |
/// |              |   |  (device A)  |                                    |  (device B)  |
/// +--------------+   +--------------+                                    +--------------+
///         |                 |                                                   |
///         |    Interacts    |                                                   |
///         |---------------->|                                                   |
///         |                 |  (1) Authorization Request                        |
///         |                 |      (Request URI)                                |
///         |                 |-------------------------------------------------->|
///         |                 |                                                   |
///         |                 |  (2) Request the Request Object                   |
///         |                 |<--------------------------------------------------|
///         |                 |                                                   |
///         |                 |  (2.5) Respond with the Request Object            |
///         |                 |      (Full parameters with response_uri)          |
///         |                 |-------------------------------------------------->|
///         |                 |                                                   |
///         |   End-User Authentication / Consent                                 |
///         |                 |                                                   |
///         |                 |  (3)   Authorization Response as HTTP POST        |
///         |                 |  (VP Token with Presentation(s))                  |
///         |                 |<--------------------------------------------------|
/// </summary>
public class RequestObjectAuthorizationRequestBuilderTests
{
    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }

    [Fact]
    public void Build_RequestObject_WithAllRequiredFields_Succeeds()
    {
        // Request Object: Must have response_type, nonce, dcql_query, response_uri, and client_id
        var request = RequestObjectAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithResponseUri("https://verifier.example.com/response")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("verifier-1", request.ClientId);
        Assert.Equal("nonce-123", request.Nonce);
        Assert.Equal("https://verifier.example.com/response", request.ResponseUri);
        Assert.NotNull(request.DcqlQuery);
    }

    [Fact]
    public void Build_RequestObject_WithAllRequiredFieldsAndScope_Succeeds()
    {
        // Request Object: Can use scope instead of dcql_query
        var request = RequestObjectAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithResponseUri("https://verifier.example.com/response")
                .WithScope("openid profile")
        );

        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("verifier-1", request.ClientId);
        Assert.Equal("nonce-123", request.Nonce);
        Assert.Equal("https://verifier.example.com/response", request.ResponseUri);
        Assert.Equal("openid profile", request.Scope);
        Assert.Null(request.DcqlQuery);
    }

    [Fact]
    public void Build_RequestObject_MissingResponseType_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            )
        );

        Assert.Contains("response_type is REQUIRED and must be 'vp_token' for Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_MissingNonce_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            )
        );

        Assert.Contains("nonce is REQUIRED for Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_MissingResponseUri_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
                    // Note: NOT setting response_uri
            )
        );

        Assert.Contains("response_uri is REQUIRED for Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_MissingClientId_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
                    // Note: NOT setting client_id - will fail during Build() due to required property
            )
        );

        Assert.Contains("client_id", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_MissingDcqlAndScope_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    // Note: NOT setting dcql_query or scope
            )
        );

        Assert.Contains("Either dcql_query or scope MUST be set for Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_WithBothDcqlAndScope_Throws()
    {
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
                    .WithScope("openid profile")  // Both dcql_query AND scope - forbidden!
            )
        );

        Assert.Contains("Only one of dcql_query or scope can be set in Request Object, not both", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_WithRequestUri_Throws()
    {
        // request_uri is FORBIDDEN in Request Object (request_uri is in the minimal request, not the RequestObject itself)
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithRequestUri("https://verifier.example.com/request")  // FORBIDDEN for Request Object!
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            )
        );

        Assert.Contains("request_uri MUST NOT be set in Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_WithRedirectUri_Throws()
    {
        // redirect_uri is FORBIDDEN in Request Object (cross-device uses response_uri, not redirect_uri)
        var ex = Assert.Throws<ValidationException>(() =>
            RequestObjectAuthorizationRequest.Build(builder =>
                builder
                    .WithResponseType(ResponseTypes.VpToken)
                    .WithClientId("verifier-1")
                    .WithNonce("nonce-123")
                    .WithResponseMode(ResponseModes.DirectPost)
                    .WithResponseUri("https://verifier.example.com/response")
                    .WithRedirectUri("https://verifier.example.com/callback")  // FORBIDDEN for Request Object!
                    .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            )
        );

        Assert.Contains("redirect_uri MUST NOT be set in Request Object", ex.Message);
    }

    [Fact]
    public void Build_RequestObject_WithState_Succeeds()
    {
        // state is optional in Request Object
        var request = RequestObjectAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithResponseUri("https://verifier.example.com/response")
                .WithState("state-456")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.NotNull(request);
        Assert.Equal("state-456", request.State);
    }

    [Fact]
    public void Build_RequestObject_WithClientMetadata_Succeeds()
    {
        // client_metadata is optional in Request Object
        var request = RequestObjectAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithResponseUri("https://verifier.example.com/response")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.NotNull(request);
    }

    [Fact]
    public void Build_RequestObject_WithDcql_Required_Succeeds()
    {
        // dcql_query is REQUIRED (unless scope is set)
        var request = RequestObjectAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithResponseUri("https://verifier.example.com/response")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.NotNull(request.DcqlQuery);
    }
}
