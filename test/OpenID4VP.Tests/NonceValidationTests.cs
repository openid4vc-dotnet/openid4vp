using OpenID4VP.Builders;
using OpenID4VC.Core.Tests;
using OpenID4VC.Core.Validation;

namespace OpenID4VP.Tests;

/// <summary>
/// Tests for nonce validation per OpenID4VP Spec Section 5.2.
/// 
/// Spec: "nonce: REQUIRED. A case-sensitive String... Values MUST only contain ASCII URL safe characters."
/// Valid characters: A-Z, a-z, 0-9, - (hyphen), . (period), _ (underscore), ~ (tilde)
/// Per RFC 3986 unreserved characters.
/// </summary>
public class NonceValidationTests
{
    [Fact]
    public void ValidationPatterns_IsValidNonce_WithValidSimpleNonce_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce-123"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithValidComplexNonce_ReturnsTrue()
    {
        // Test all valid characters: letters, digits, hyphen, period, underscore, tilde
        Assert.True(ValidationPatterns.IsValidNonce("n-0S6_WzA2Mj"));
        Assert.True(ValidationPatterns.IsValidNonce("abc.def~123"));
        Assert.True(ValidationPatterns.IsValidNonce("A_B-C.D~E"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithOnlyLetters_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce"));
        Assert.True(ValidationPatterns.IsValidNonce("AbCdEf"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithOnlyDigits_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("123456"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithHyphen_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce-value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithPeriod_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce.value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithUnderscore_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce_value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithTilde_ReturnsTrue()
    {
        Assert.True(ValidationPatterns.IsValidNonce("nonce~value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithSpace_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithAtSign_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce@value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithColon_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce:value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithForwardSlash_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce/value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithQuestionMark_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce?value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithEquals_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce=value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithAmpersand_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce&value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithPlusSign_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce+value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithHash_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce#value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithPercent_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce%value"));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithNull_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce(null));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithEmptyString_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce(""));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithWhitespace_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("   "));
    }

    [Fact]
    public void ValidationPatterns_IsValidNonce_WithUnicodeCharacters_ReturnsFalse()
    {
        Assert.False(ValidationPatterns.IsValidNonce("nonce_ü"));
        Assert.False(ValidationPatterns.IsValidNonce("nonce_例え"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_ValidNonce_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")  // Valid nonce
            .WithResponseMode("fragment")
            .Build();

        var request = result.AssertSuccess();
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_InvalidNonce_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce@invalid")  // Invalid: contains @
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_WithSpace_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce with space")
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_WithColon_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce:value")
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_WithForwardSlash_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce/value")
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_WithUnicode_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce_ü")  // Unicode character
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_MultipleErrors_IncludesNonceError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithNonce("invalid@nonce")
            // Missing required: client_id, response_mode
            .Build();

        var errors = result.AssertError();
        // Should have error for invalid nonce
        Assert.Contains(errors, e => e.Message.Contains("ASCII URL safe characters"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithValidNonceContainingAllAllowedSpecialChars_Succeeds()
    {
        // Test nonce with hyphen, period, underscore, tilde
        var complexNonce = "test-nonce.value_123~end";
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce(complexNonce)
            .WithResponseMode("fragment")
            .Build();

        var request = result.AssertSuccess();
        Assert.Equal(complexNonce, request.Nonce);
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_EmptyString_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("")
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        // Empty string is caught by the "required" validation first
        Assert.Contains(errors, e => e.Message.Contains("required"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_Null_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce(null)
            .WithResponseMode("fragment")
            .Build();

        var errors = result.AssertError();
        // Null is caught by the "required" validation
        Assert.Contains(errors, e => e.Message.Contains("required"));
    }

    [Fact]
    public void AuthorizationRequestBuilder_WithNonce_SpecCharactersNotAllowed_ReturnsError()
    {
        // Test common special characters that should NOT be allowed
        var invalidChars = new[] { "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", "|", ";", ":", "'", "\"", "<", ">", ",", "?" };
        
        foreach (var invalidChar in invalidChars)
        {
            var nonce = $"nonce{invalidChar}value";
            var result = AuthorizationRequestBuilder.Create()
                .WithClientId("https://verifier.example.com")
                .WithNonce(nonce)
                .WithResponseMode("fragment")
                .Build();

            var errors = result.AssertError();
            Assert.True(errors.Any(e => e.Message.Contains("ASCII URL safe characters")), 
                $"Nonce with '{invalidChar}' should fail validation");
        }
    }
}
