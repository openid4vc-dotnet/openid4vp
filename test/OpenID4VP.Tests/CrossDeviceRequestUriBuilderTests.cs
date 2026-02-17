using OpenID4VP.Builders;
using OpenID4VC.Core.Results;
using OpenID4VC.Core.Tests;
using Xunit;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for CrossDeviceRequestUriBuilder - URI generation for cross-device QR code scenarios.
/// 
/// Per OpenID4VP Spec Section 3.2, cross-device flow generates minimal requests containing only:
/// - client_id (REQUIRED)
/// - request_uri (REQUIRED)  
/// - nonce (REQUIRED per Section 5.2)
/// - state (OPTIONAL)
/// - request_uri_method (OPTIONAL, must be "get" or "post")
/// - custom parameters (OPTIONAL via .WithParameter())
///
/// The builder directly generates query string URIs suitable for QR code encoding,
/// without the intermediate step of building an AuthorizationRequest object.
/// </summary>
public class CrossDeviceRequestUriBuilderTests
{
    [Fact]
    public void Build_MinimalRequest_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz_-~.")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.NotNull(result.Value);
        Assert.Contains("client_id=verifier-1", result.Value);
        Assert.Contains("request_uri=https%3A%2F%2Fverifier.example.com%2Frequest", result.Value);
        Assert.Contains("nonce=abc123xyz_-~.", result.Value);
    }

    [Fact]
    public void Build_MissingClientId_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_MissingRequestUri_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_MissingNonce_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_InvalidRequestUri_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("not-a-valid-uri")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_NonceWithInvalidCharacters_ReturnsFailure()
    {
        // Arrange - nonce contains space and special chars (invalid per RFC 3986)
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc 123 xyz!")  // spaces and ! are invalid
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_MissingBaseUri_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .Build("");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_WithCustomParameter_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithParameter("custom_param", "custom_value")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("custom_param=custom_value", result.Value);
    }

    [Fact]
    public void Build_WithMultipleCustomParameters_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithParameter("param1", "value1")
            .WithParameter("param2", "value2")
            .WithParameter("param3", "value3")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("param1=value1", result.Value);
        Assert.Contains("param2=value2", result.Value);
        Assert.Contains("param3=value3", result.Value);
    }

    [Fact]
    public void Build_WithDuplicateCustomParameter_LastValueWins()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithParameter("param", "value1")
            .WithParameter("param", "value2")  // overwrite
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("param=value2", result.Value);
        Assert.DoesNotContain("param=value1", result.Value);
    }

    [Fact]
    public void Build_UriEncoding_SpecialCharactersEncoded()
    {
        // Arrange - request_uri with special characters should be encoded
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request?id=123&type=test")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        // Query string parameters should be URL-encoded
        Assert.Contains("request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%3Fid%3D123%26type%3DTest", 
            result.Value, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_BaseUriWithExistingQuery_AppendsWithAmpersand()
    {
        // Arrange - base URI already has query params
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr?existing=param");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("existing=param&", result.Value);
    }

    [Fact]
    public void Build_BaseUriWithoutQuery_AppendsWithQuestion()
    {
        // Arrange - base URI has no query params
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("?client_id=", result.Value);
    }

    [Fact]
    public void Build_NonceAllowsRfc3986UnreservedCharacters()
    {
        // Arrange - all RFC 3986 unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
        var nonce = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce(nonce)
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
    }

    [Theory]
    [InlineData("nonce with space")]
    [InlineData("nonce@with#special")]
    [InlineData("nonce/with/slash")]
    [InlineData("nonce%with%percent")]
    [InlineData("nonce&with&ampersand")]
    public void Build_NonceWithInvalidCharacters_AllFail(string invalidNonce)
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce(invalidNonce)
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
    }

    [Fact]
    public void Build_CompleteQrCodeScenario()
    {
        // Arrange - realistic QR code generation scenario
        var baseUri = "https://qr.verifier.com/auth";
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-qr-1")
            .WithRequestUri("https://verifier.example.com/request/req-2024-001")
            .WithNonce("sYjRYk-KX3J9mZ2w1kLPnQuC9nv")
            .WithParameter("version", "1.0")
            .Build(baseUri);

        // Act
        result.AssertSuccess();
        var qrUri = result.Value;

        // Assert - verify all required and optional params are present
        Assert.StartsWith(baseUri, qrUri);
        Assert.Contains("client_id=verifier-qr-1", qrUri);
        Assert.Contains("request_uri=", qrUri);
        Assert.Contains("nonce=sYjRYk-KX3J9mZ2w1kLPnQuC9nv", qrUri);
        Assert.Contains("version=1.0", qrUri);
    }

    [Fact]
    public void Build_FluentChaining_Works()
    {
        // Arrange - verify fluent API works correctly without breaking chain
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("test")
            .WithRequestUri("https://example.com/req")
            .WithNonce("nonce123")
            .WithParameter("a", "1")
            .WithParameter("b", "2")
            .WithParameter("c", "3")
            .Build("https://example.com");

        // Act & Assert
        result.AssertSuccess();
        Assert.NotEmpty(result.Value);
    }

    [Fact]
    public void Build_WithRequestUriMethod_Get_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("get")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("request_uri_method=get", result.Value);
    }

    [Fact]
    public void Build_WithRequestUriMethod_Post_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("post")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("request_uri_method=post", result.Value);
    }

    [Fact]
    public void Build_WithRequestUriMethod_CaseInsensitive_NormalizesToLowercase()
    {
        // Arrange - test various case combinations
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("POST")  // uppercase
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        // Should be normalized to lowercase
        Assert.Contains("request_uri_method=post", result.Value);
        Assert.DoesNotContain("request_uri_method=POST", result.Value);
    }

    [Fact]
    public void Build_WithRequestUriMethod_MixedCase_NormalizesToLowercase()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("Get")  // mixed case
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("request_uri_method=get", result.Value);
    }

    [Fact]
    public void Build_WithoutRequestUriMethod_SucceedsAndNotInQueryString()
    {
        // Arrange - no WithRequestUriMethod call
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        // Should not include request_uri_method in query string
        Assert.DoesNotContain("request_uri_method", result.Value);
    }

    [Fact]
    public void Build_WithRequestUriMethod_InvalidMethod_ReturnsFailure()
    {
        // Arrange - invalid method value
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("put")  // invalid - only get/post allowed
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_WithRequestUriMethod_Delete_ReturnsFailure()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithRequestUriMethod("delete")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertError();
        Assert.Single(result.Errors, e => e.Code == "validation_error");
    }

    [Fact]
    public void Build_WithState_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithState("state456")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("state=state456", result.Value);
    }

    [Fact]
    public void Build_WithStateAndRequestUriMethod_Succeeds()
    {
        // Arrange
        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithNonce("abc123xyz")
            .WithState("state789")
            .WithRequestUriMethod("post")
            .Build("https://auth.example.com/qr");

        // Act & Assert
        result.AssertSuccess();
        Assert.Contains("state=state789", result.Value);
        Assert.Contains("request_uri_method=post", result.Value);
    }
}
