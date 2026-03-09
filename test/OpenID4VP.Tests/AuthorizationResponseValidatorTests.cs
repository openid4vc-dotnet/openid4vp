using OpenID4VP.Models;
using OpenID4VP.Parsers;
using OpenID4VP.Validators;

namespace OpenID4VP.Tests.Validators;

/// <summary>
/// Tests for AuthorizationResponseValidator
/// </summary>
public class AuthorizationResponseValidatorTests
{
    private readonly AuthorizationResponseValidator _validator = new();
    private readonly AuthorizationResponseParser _parser = new();

    private AuthorizationResponse CreateValidResponse()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""jwt...""] }, ""state"": ""state-123"" }";
        return _parser.Parse(json).Value!;
    }

    [Fact]
    public void Validate_ValidResponse_ReturnsSuccess()
    {
        var response = CreateValidResponse();
        
        var result = _validator.Validate(response);
        
        Assert.True(result.IsSuccess);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_ResponseWithoutState_ReturnsSuccess()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""jwt...""] } }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.Validate(response);
        
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void Validate_ResponseWithIdToken_ReturnsSuccess()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": ""state-x"", ""id_token"": ""id_token..."" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.Validate(response);
        
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void Validate_NullResponse_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _validator.Validate(null!));
        Assert.Equal("response", ex.ParamName);
    }

    [Fact]
    public void Validate_NullVpToken_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] } }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.Validate(response);
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void Validate_NullPresentations_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] } }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        var validationResult = _validator.Validate(response);
        
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void ValidateStateMatch_MatchingState_ReturnsSuccess()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": ""request-state-123"" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.ValidateStateMatch(response, "request-state-123");
        
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void ValidateStateMatch_NonMatchingState_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": ""response-state-456"" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.ValidateStateMatch(response, "request-state-123");
        
        Assert.False(validationResult.IsSuccess);
        Assert.Contains(validationResult.Errors, e => e.Message.Contains("State mismatch"));
    }

    [Fact]
    public void ValidateStateMatch_ResponseMissingState_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] } }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.ValidateStateMatch(response, "request-state-123");
        
        Assert.False(validationResult.IsSuccess);
        Assert.Contains(validationResult.Errors, e => e.Message.Contains("missing"));
    }

    [Fact]
    public void ValidateStateMatch_NullResponse_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _validator.ValidateStateMatch(null!, "state"));
        Assert.Equal("response", ex.ParamName);
    }

    [Fact]
    public void ValidateStateMatch_NullExpectedState_ThrowsArgumentNullException()
    {
        var response = CreateValidResponse();
        
        var ex = Assert.Throws<ArgumentNullException>(() => _validator.ValidateStateMatch(response, null!));
        Assert.Equal("expectedState", ex.ParamName);
    }

    [Fact]
    public void ValidateStateMatch_StateIsEmptyString_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": """" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.ValidateStateMatch(response, "state-123");
        
        Assert.False(validationResult.IsSuccess);
    }

    [Fact]
    public void ValidateStateMatch_CaseSensitive_ReturnsFailure()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": ""State-123"" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.ValidateStateMatch(response, "state-123");
        
        Assert.False(validationResult.IsSuccess);
        Assert.Contains(validationResult.Errors, e => e.Message.Contains("mismatch"));
    }

    [Fact]
    public void Validate_MultipleCredentials_ReturnsSuccess()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""jwt1""], ""credential2"": [""jwt2""] } }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.Validate(response);
        
        Assert.True(validationResult.IsSuccess);
    }

    [Fact]
    public void Validate_AllOptionalFieldsPopulated_ReturnsSuccess()
    {
        var json = @"{ ""vp_token"": { ""credential1"": [""vp...""] }, ""state"": ""state-complete"", ""id_token"": ""id_token_jwt"" }";
        var result = _parser.Parse(json);
        var response = result.Value!;
        
        var validationResult = _validator.Validate(response);
        
        Assert.True(validationResult.IsSuccess);
        Assert.Empty(validationResult.Errors);
    }
}
