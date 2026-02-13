using OpenID4VC.Core.Results;

namespace OpenID4VC.Core.Tests.Results;

/// <summary>
/// Tests for error types (ValidationError, ParseError, DomainError, ExternalError).
/// Ensures errors are properly classified and extensible.
/// </summary>
public class ErrorTests
{
    [Fact]
    public void ValidationError_WithPropertyName_ContainsPropertyInfo()
    {
        // Arrange & Act
        var error = new ValidationError("field is required", "fieldName");

        // Assert
        Assert.Equal("validation_error", error.Code);
        Assert.Equal("field is required", error.Message);
        Assert.Equal("fieldName", error.PropertyName);
    }

    [Fact]
    public void ValidationError_WithoutPropertyName_HasNullProperty()
    {
        // Arrange & Act
        var error = new ValidationError("validation failed");

        // Assert
        Assert.Equal("validation_error", error.Code);
        Assert.Equal("validation failed", error.Message);
        Assert.Null(error.PropertyName);
    }

    [Fact]
    public void ParseError_WithInputValue_ContainsInputInfo()
    {
        // Arrange & Act
        var error = new ParseError("Invalid JSON", "{invalid}");

        // Assert
        Assert.Equal("parse_error", error.Code);
        Assert.Equal("Invalid JSON", error.Message);
        Assert.Equal("{invalid}", error.InputValue);
    }

    [Fact]
    public void ParseError_WithoutInputValue_HasNullInputValue()
    {
        // Arrange & Act
        var error = new ParseError("Failed to parse JWT");

        // Assert
        Assert.Equal("parse_error", error.Code);
        Assert.Equal("Failed to parse JWT", error.Message);
        Assert.Null(error.InputValue);
    }

    [Fact]
    public void DomainError_WithDomainCode_ContainsDomainInfo()
    {
        // Arrange & Act
        var error = new DomainError("Insufficient balance", "insufficient_balance");

        // Assert
        Assert.Equal("domain_error", error.Code);
        Assert.Equal("Insufficient balance", error.Message);
        Assert.Equal("insufficient_balance", error.DomainCode);
    }

    [Fact]
    public void DomainError_WithoutDomainCode_HasNullDomainCode()
    {
        // Arrange & Act
        var error = new DomainError("Business rule violated");

        // Assert
        Assert.Equal("domain_error", error.Code);
        Assert.Equal("Business rule violated", error.Message);
        Assert.Null(error.DomainCode);
    }

    [Fact]
    public void ExternalError_WithSystemAndStatusCode_ContainsExternalInfo()
    {
        // Arrange & Act
        var error = new ExternalError("Service unavailable", "CredentialService", 503);

        // Assert
        Assert.Equal("external_error", error.Code);
        Assert.Equal("Service unavailable", error.Message);
        Assert.Equal("CredentialService", error.ExternalSystem);
        Assert.Equal(503, error.HttpStatusCode);
    }

    [Fact]
    public void ExternalError_WithoutExternalInfo_HasNullFields()
    {
        // Arrange & Act
        var error = new ExternalError("External call failed");

        // Assert
        Assert.Equal("external_error", error.Code);
        Assert.Equal("External call failed", error.Message);
        Assert.Null(error.ExternalSystem);
        Assert.Null(error.HttpStatusCode);
    }

    [Fact]
    public void Error_ToString_FormatsAsCodeAndMessage()
    {
        // Arrange
        Error error = new ValidationError("Invalid input", "email");

        // Act
        var str = error.ToString();

        // Assert
        Assert.Contains("[validation_error]", str);
        Assert.Contains("Invalid input", str);
    }

    [Fact]
    public void ErrorsCanBeMixedInSingleResult()
    {
        // Arrange & Act
        var result = Result<string>.Failure(
            new ValidationError("Email is required", "email"),
            new ValidationError("Password too short", "password"),
            new DomainError("Account locked", "account_locked")
        );

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal(3, result.Errors.Count);
        Assert.IsType<ValidationError>(result.Errors[0]);
        Assert.IsType<ValidationError>(result.Errors[1]);
        Assert.IsType<DomainError>(result.Errors[2]);
    }

    [Fact]
    public void CustomErrorType_CanExtendErrorBase()
    {
        // Arrange
        var customError = new CustomTestError("custom error message");

        // Act & Assert
        Assert.Equal("custom_error", customError.Code);
        Assert.Equal("custom error message", customError.Message);
        Assert.True(customError.IsCustom);
    }

    /// <summary>
    /// Test custom error type to demonstrate extensibility.
    /// </summary>
    private sealed class CustomTestError : Error
    {
        public bool IsCustom { get; } = true;

        public CustomTestError(string message)
            : base("custom_error", message)
        {
        }
    }
}
