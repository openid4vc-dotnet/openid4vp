using OpenID4VC.Core.Results;

namespace OpenID4VC.Core.Tests;

/// <summary>
/// Comprehensive tests for Result<T> implicit operators.
/// Tests bidirectional conversions between Result<T>, T, Error, and Error[]
/// to ensure type-safe, boilerplate-free error handling in builders.
/// </summary>
public class ResultImplicitOperatorsTests
{
    // ========== PART 1: Wrapping Operators (T → Result<T>) ==========

    [Fact]
    public void ImplicitOperator_ValueToResult_BasicString()
    {
        // Arrange
        var value = "test-value";

        // Act
        Result<string> result = value;

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("test-value", result.Value);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void ImplicitOperator_ValueToResult_Integer()
    {
        // Arrange
        var value = 42;

        // Act
        Result<int> result = value;

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void ImplicitOperator_ValueToResult_Boolean()
    {
        // Arrange
        var value = true;

        // Act
        Result<bool> result = value;

        // Assert
        Assert.True(result.IsSuccess);
        Assert.True(result.Value);
    }

    [Fact]
    public void ImplicitOperator_ValueToResult_WithNullString()
    {
        // Arrange
        string? value = null;

        // Act
        Result<string?> result = value;

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Null(result.Value);
    }

    [Fact]
    public void ImplicitOperator_ValueToResult_WithComplexObject()
    {
        // Arrange
        var person = new { Name = "John", Age = 30 };

        // Act
        Result<object> result = person;

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Same(person, result.Value);
    }

    [Fact]
    public void ImplicitOperator_ValueToResult_Chainable()
    {
        // Arrange
        var initialValue = 5;

        // Act: Chain implicit operators with Map
        Result<int> result = initialValue;
        var mapped = result
            .Map(x => x * 2)
            .Map(x => x + 3);
        int final = mapped;

        // Assert
        Assert.Equal(13, final);  // (5 * 2) + 3
    }

    // ========== PART 2: Wrapping Operators (Error → Result<T>) ==========

    [Fact]
    public void ImplicitOperator_ErrorToResult_ValidationError()
    {
        // Arrange
        var error = new ValidationError("field required", "Name");

        // Act
        Result<string> result = error;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Same(error, result.Errors[0]);
    }

    [Fact]
    public void ImplicitOperator_ErrorToResult_ParseError()
    {
        // Arrange
        var error = new ParseError("invalid format", "2026-13-45");

        // Act
        Result<int> result = error;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void ImplicitOperator_ErrorToResult_DomainError()
    {
        // Arrange
        var error = new DomainError("DUPLICATE_ENTRY", "Entity already exists");

        // Act
        Result<string> result = error;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.IsType<DomainError>(result.Errors[0]);
    }

    [Fact]
    public void ImplicitOperator_ErrorToResult_ExternalError()
    {
        // Arrange
        var error = new ExternalError("ServiceA", "Service unavailable", 503);

        // Act
        Result<string> result = error;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.IsType<ExternalError>(result.Errors[0]);
    }

    // ========== PART 3: Wrapping Operators (Error[] → Result<T>) ==========

    [Fact]
    public void ImplicitOperator_ErrorArrayToResult_SingleError()
    {
        // Arrange
        var errors = new Error[] { new ValidationError("required") };

        // Act
        Result<string> result = errors;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
    }

    [Fact]
    public void ImplicitOperator_ErrorArrayToResult_MultipleErrors()
    {
        // Arrange
        var errors = new Error[]
        {
            new ValidationError("error 1"),
            new ValidationError("error 2"),
            new ValidationError("error 3")
        };

        // Act
        Result<string> result = errors;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal(3, result.Errors.Count);
    }

    [Fact]
    public void ImplicitOperator_ErrorArrayToResult_EmptyArray_ThrowsArgumentException()
    {
        // Arrange
        Error[] emptyErrors = [];

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
        {
            Result<string> result = emptyErrors;
        });
        Assert.Contains("At least one error must be provided", ex.Message);
    }

    [Fact]
    public void ImplicitOperator_ErrorArrayToResult_MixedErrorTypes()
    {
        // Arrange
        var errors = new Error[]
        {
            new ValidationError("validation failed"),
            new ParseError("parse failed", "invalid-input"),
            new DomainError("RULE_VIOLATION", "business rule broken"),
            new ExternalError("API", "timeout", 504)
        };

        // Act
        Result<string> result = errors;

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal(4, result.Errors.Count);
        Assert.IsType<ValidationError>(result.Errors[0]);
        Assert.IsType<ParseError>(result.Errors[1]);
        Assert.IsType<DomainError>(result.Errors[2]);
        Assert.IsType<ExternalError>(result.Errors[3]);
    }

    [Fact]
    public void ImplicitOperator_ErrorArrayToResult_FromList()
    {
        // Arrange
        var errorList = new List<Error>
        {
            new ValidationError("error 1"),
            new ValidationError("error 2")
        };

        // Act
        Result<string> result = errorList.ToArray();

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal(2, result.Errors.Count);
    }

    // ========== PART 4: Round-Trip Conversions ==========

    [Fact]
    public void ImplicitOperator_RoundTrip_SuccessValue()
    {
        // Arrange
        var originalValue = "test-data";

        // Act
        Result<string> result = originalValue;       // Wrap: T → Result<T>
        string recovered = result;                    // Unwrap: Result<T> → T

        // Assert
        Assert.Equal(originalValue, recovered);
    }

    [Fact]
    public void ImplicitOperator_RoundTrip_FailureError()
    {
        // Arrange
        var originalError = new ValidationError("message", "field");

        // Act
        Result<string> result = originalError;       // Wrap: Error → Result<T>
        Error recovered = result;                     // Unwrap: Result<T> → Error

        // Assert
        Assert.Same(originalError, recovered);
    }

    [Fact]
    public void ImplicitOperator_RoundTrip_FailureErrorArray()
    {
        // Arrange
        var originalErrors = new Error[]
        {
            new ValidationError("error 1"),
            new ValidationError("error 2")
        };

        // Act
        Result<string> result = originalErrors;      // Wrap: Error[] → Result<T>
        Error[] recovered = result;                   // Unwrap: Result<T> → Error[]

        // Assert
        Assert.Equal(2, recovered.Length);
        Assert.Equal(originalErrors, recovered);
    }

    [Fact]
    public void ImplicitOperator_RoundTrip_ChainedConversions()
    {
        // Arrange
        var value1 = 42;

        // Act
        Result<int> result1 = value1;                 // Wrap
        int unwrapped = result1;                      // Unwrap
        Result<int> result2 = unwrapped;              // Re-wrap
        int final = result2;                          // Final unwrap

        // Assert
        Assert.Equal(42, final);
    }

    // ========== PART 5: Real-World Builder Scenarios ==========

    [Fact]
    public void ImplicitOperator_Builder_SuccessReturnPattern()
    {
        // Arrange & Act: Simulates AuthorizationRequestBuilder.Build() pattern
        Result<TestAuthorizationRequest> BuildSuccessfully(string clientId)
        {
            var request = new TestAuthorizationRequest { ClientId = clientId };
            return request;  // Implicit T → Result<T>
        }

        var result = BuildSuccessfully("my-client-id");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("my-client-id", result.Value!.ClientId);
    }

    [Fact]
    public void ImplicitOperator_Builder_FailureReturnPattern()
    {
        // Arrange & Act: Simulates validation failure in builder
        Result<TestAuthorizationRequest> BuildWithValidation(string? clientId)
        {
            if (string.IsNullOrEmpty(clientId))
                return new ValidationError("client_id is required", "ClientId");  // Implicit Error → Result<T>

            return new TestAuthorizationRequest { ClientId = clientId };  // Implicit T → Result<T>
        }

        var result = BuildWithValidation(null);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.IsType<ValidationError>(result.Errors[0]);
    }

    [Fact]
    public void ImplicitOperator_Builder_MultipleErrorsReturnPattern()
    {
        // Arrange & Act: Simulates validation of multiple fields
        Result<TestAuthorizationRequest> ValidateRequest(string? clientId, string? responseMode)
        {
            var errors = new List<Error>();

            if (string.IsNullOrEmpty(clientId))
                errors.Add(new ValidationError("required", "ClientId"));

            if (string.IsNullOrEmpty(responseMode))
                errors.Add(new ValidationError("required", "ResponseMode"));

            if (errors.Any())
                return errors.ToArray();  // Implicit Error[] → Result<T>

            return new TestAuthorizationRequest
            {
                ClientId = clientId,
                ResponseMode = responseMode
            };  // Implicit T → Result<T>
        }

        var result = ValidateRequest(null, null);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Equal(2, result.Errors.Count);
    }

    [Fact]
    public void ImplicitOperator_ScenarioBuilder_CompositionPattern()
    {
        // Arrange & Act: Simulates SameDeviceAuthorizationRequest.Build() pattern
        Result<TestAuthorizationRequest> BuildWithScenarioValidation(
            Action<TestAuthorizationRequestBuilder> configure)
        {
            // 1. Create and configure base builder
            var builder = new TestAuthorizationRequestBuilder();
            configure(builder);

            // 2. Build and check for failures
            var buildResult = builder.Build();
            if (!buildResult.IsSuccess)
                return buildResult.Errors.ToArray();  // Implicit Error[] → Result<T>

            // 3. Run scenario-specific validation
            var request = buildResult.Value!;
            var validationErrors = ValidateForSameDevice(request);
            if (validationErrors.Length > 0)
                return validationErrors;  // Implicit Error[] → Result<T>

            // 4. Return success
            return request;  // Implicit T → Result<T>
        }

        // Act
        var result = BuildWithScenarioValidation(b => b.WithClientId("client-id"));

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("client-id", result.Value!.ClientId);
    }

    // ========== Helper Methods and Test Models ==========

    private static Error[] ValidateForSameDevice(TestAuthorizationRequest request)
    {
        var errors = new List<Error>();

        if (string.IsNullOrEmpty(request.ClientId))
            errors.Add(new ValidationError("required", "ClientId"));

        return errors.ToArray();
    }

    /// <summary>
    /// Test model simulating AuthorizationRequest from OpenID4VP
    /// </summary>
    private class TestAuthorizationRequest
    {
        public string? ClientId { get; set; }
        public string? ResponseMode { get; set; }
    }

    /// <summary>
    /// Test builder simulating AuthorizationRequestBuilder pattern
    /// </summary>
    private class TestAuthorizationRequestBuilder
    {
        private string? _clientId;
        private string? _responseMode = "direct_post";

        public TestAuthorizationRequestBuilder WithClientId(string clientId)
        {
            _clientId = clientId;
            return this;
        }

        public TestAuthorizationRequestBuilder WithResponseMode(string responseMode)
        {
            _responseMode = responseMode;
            return this;
        }

        public Result<TestAuthorizationRequest> Build()
        {
            if (string.IsNullOrEmpty(_clientId))
                return new ValidationError("client_id is required", "ClientId");  // Implicit Error → Result<T>

            if (string.IsNullOrEmpty(_responseMode))
                return new ValidationError("response_mode is required", "ResponseMode");

            var request = new TestAuthorizationRequest
            {
                ClientId = _clientId,
                ResponseMode = _responseMode
            };

            return request;  // Implicit T → Result<T>
        }
    }
}
