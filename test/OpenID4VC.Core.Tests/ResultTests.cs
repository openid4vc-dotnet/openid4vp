using OpenID4VC.Core.Results;

namespace OpenID4VC.Core.Tests.Results;

/// <summary>
/// Tests for the Result<T> pattern - success and failure creation, composition, and error handling.
/// </summary>
public class ResultTests
{
    [Fact]
    public void Success_CreatesSuccessfulResult_WithValue()
    {
        // Arrange
        const string expectedValue = "test";

        // Act
        var result = Result<string>.Success(expectedValue);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(expectedValue, result.Value);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Failure_WithSingleError_CreatesFailedResult()
    {
        // Arrange
        var error = new ValidationError("Invalid value", "field");

        // Act
        var result = Result<string>.Failure(error);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Single(result.Errors);
        Assert.Equal(error, result.Errors[0]);
    }

    [Fact]
    public void Failure_WithMultipleErrors_CreatesFailedResult()
    {
        // Arrange
        var error1 = new ValidationError("Invalid value", "field1");
        var error2 = new ValidationError("Missing value", "field2");

        // Act
        var result = Result<string>.Failure(error1, error2);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Equal(2, result.Errors.Count);
        Assert.Contains(error1, result.Errors);
        Assert.Contains(error2, result.Errors);
    }

    [Fact]
    public void Failure_WithEmptyErrors_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Result<string>.Failure());
    }

    [Fact]
    public void Failure_WithEmptyEnumerable_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Result<string>.Failure(Array.Empty<Error>()));
    }

    [Fact]
    public void Map_OnSuccess_TransformsValue()
    {
        // Arrange
        var result = Result<int>.Success(5);

        // Act
        var mapped = result.Map(x => x * 2);

        // Assert
        Assert.True(mapped.IsSuccess);
        Assert.Equal(10, mapped.Value);
    }

    [Fact]
    public void Map_OnFailure_RetainsFailure()
    {
        // Arrange
        var error = new ValidationError("test error");
        var result = Result<int>.Failure(error);

        // Act
        var mapped = result.Map(x => x * 2);

        // Assert
        Assert.False(mapped.IsSuccess);
        Assert.Contains(error, mapped.Errors);
    }

    [Fact]
    public void Map_WithExceptionThrown_ReturnsFailureWithDomainError()
    {
        // Arrange
        var result = Result<int>.Success(5);

        // Act
        var mapped = result.Map<int>(x => throw new InvalidOperationException("Boom!"));

        // Assert
        Assert.False(mapped.IsSuccess);
        Assert.Single(mapped.Errors);
        Assert.IsType<DomainError>(mapped.Errors[0]);
        Assert.Contains("Transformation failed", mapped.Errors[0].Message);
    }

    [Fact]
    public void Bind_OnSuccess_ChainsResult()
    {
        // Arrange
        var result = Result<int>.Success(5);

        // Act
        var bound = result.Bind(x => Result<string>.Success(x.ToString()));

        // Assert
        Assert.True(bound.IsSuccess);
        Assert.Equal("5", bound.Value);
    }

    [Fact]
    public void Bind_OnSuccess_PropagatesFailure()
    {
        // Arrange
        var result = Result<int>.Success(5);
        var error = new ValidationError("Invalid result");

        // Act
        var bound = result.Bind(x => Result<string>.Failure(error));

        // Assert
        Assert.False(bound.IsSuccess);
        Assert.Contains(error, bound.Errors);
    }

    [Fact]
    public void Bind_OnFailure_RetainsFailure()
    {
        // Arrange
        var error = new ValidationError("original error");
        var result = Result<int>.Failure(error);

        // Act
        var bound = result.Bind(x => Result<string>.Success(x.ToString()));

        // Assert
        Assert.False(bound.IsSuccess);
        Assert.Contains(error, bound.Errors);
    }

    [Fact]
    public void Tap_OnSuccess_ExecutesSideEffect()
    {
        // Arrange
        var result = Result<string>.Success("test");
        var sideEffectExecuted = false;

        // Act
        result.Tap(_ => sideEffectExecuted = true);

        // Assert
        Assert.True(sideEffectExecuted);
    }

    [Fact]
    public void Tap_OnSuccess_ReturnsUnchangedResult()
    {
        // Arrange
        var result = Result<string>.Success("test");

        // Act
        var tapped = result.Tap(_ => { });

        // Assert
        Assert.Equal(result, tapped);
    }

    [Fact]
    public void Tap_OnFailure_DoesNotExecuteSideEffect()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));
        var sideEffectExecuted = false;

        // Act
        result.Tap(_ => sideEffectExecuted = true);

        // Assert
        Assert.False(sideEffectExecuted);
    }

    [Fact]
    public void TapError_OnFailure_ExecutesSideEffect()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));
        var sideEffectExecuted = false;

        // Act
        result.TapError(_ => sideEffectExecuted = true);

        // Assert
        Assert.True(sideEffectExecuted);
    }

    [Fact]
    public void TapError_OnFailure_ReturnsUnchangedResult()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));

        // Act
        var tapped = result.TapError(_ => { });

        // Assert
        Assert.Equal(result, tapped);
    }

    [Fact]
    public void TapError_OnSuccess_DoesNotExecuteSideEffect()
    {
        // Arrange
        var result = Result<string>.Success("test");
        var sideEffectExecuted = false;

        // Act
        result.TapError(_ => sideEffectExecuted = true);

        // Assert
        Assert.False(sideEffectExecuted);
    }

    [Fact]
    public void GetValueOrThrow_OnSuccess_ReturnsValue()
    {
        // Arrange
        var result = Result<string>.Success("test");

        // Act
        var value = result.GetValueOrThrow();

        // Assert
        Assert.Equal("test", value);
    }

    [Fact]
    public void GetValueOrThrow_OnFailure_ThrowsException()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));

        // Act & Assert
        Assert.Throws<ApplicationException>(() => result.GetValueOrThrow());
    }

    [Fact]
    public void GetValueOrThrow_WithCustomException_OnFailure_ThrowsCustomException()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            result.GetValueOrThrow(errors => new InvalidOperationException("Custom: " + errors[0].Message))
        );
        Assert.Contains("Custom", ex.Message);
    }

    [Fact]
    public void Match_OnSuccess_CallsSuccessHandler()
    {
        // Arrange
        var result = Result<int>.Success(5);
        var successCalled = false;

        // Act
        var value = result.Match(
            onSuccess: x => { successCalled = true; return x * 2; },
            onFailure: _ => -1
        );

        // Assert
        Assert.True(successCalled);
        Assert.Equal(10, value);
    }

    [Fact]
    public void Match_OnFailure_CallsFailureHandler()
    {
        // Arrange
        var error = new ValidationError("test error");
        var result = Result<int>.Failure(error);
        var failureCalled = false;

        // Act
        var value = result.Match(
            onSuccess: _ => -1,
            onFailure: errors => { failureCalled = true; return errors.Count; }
        );

        // Assert
        Assert.True(failureCalled);
        Assert.Equal(1, value);
    }

    [Fact]
    public void MatchVoid_OnSuccess_CallsSuccessHandler()
    {
        // Arrange
        var result = Result<int>.Success(5);
        var successCalled = false;

        // Act
        result.Match(
            onSuccess: _ => successCalled = true,
            onFailure: _ => { }
        );

        // Assert
        Assert.True(successCalled);
    }

    [Fact]
    public void MatchVoid_OnFailure_CallsFailureHandler()
    {
        // Arrange
        var error = new ValidationError("test error");
        var result = Result<int>.Failure(error);
        var failureCalled = false;

        // Act
        result.Match(
            onSuccess: _ => { },
            onFailure: _ => failureCalled = true
        );

        // Assert
        Assert.True(failureCalled);
    }

    [Fact]
    public void Or_OnSuccess_ReturnsOriginalValue()
    {
        // Arrange
        var result = Result<int>.Success(5);

        // Act
        var recovered = result.Or(_ => 10);

        // Assert
        Assert.True(recovered.IsSuccess);
        Assert.Equal(5, recovered.Value);
    }

    [Fact]
    public void Or_OnFailure_ReturnsRecoveredValue()
    {
        // Arrange
        var result = Result<int>.Failure(new ValidationError("error"));

        // Act
        var recovered = result.Or(_ => 10);

        // Assert
        Assert.True(recovered.IsSuccess);
        Assert.Equal(10, recovered.Value);
    }

    [Fact]
    public void Or_OnFailure_WithExceptionInRecovery_ReturnsFailureWithDomainError()
    {
        // Arrange
        var result = Result<int>.Failure(new ValidationError("error"));

        // Act
        var recovered = result.Or(_ => throw new InvalidOperationException("Recovery failed"));

        // Assert
        Assert.False(recovered.IsSuccess);
        Assert.Single(recovered.Errors);
        Assert.IsType<DomainError>(recovered.Errors[0]);
    }

    [Fact]
    public void Composition_ChainMultipleOperations()
    {
        // Arrange
        var result = Result<int>.Success(5);

        // Act
        var final = result
            .Map(x => x * 2)                          // 10
            .Map(x => x + 5)                          // 15
            .Bind(x => Result<int>.Success(x / 3))    // 5
            .Map(x => x.ToString());                  // "5"

        // Assert
        Assert.True(final.IsSuccess);
        Assert.Equal("5", final.Value);
    }

    [Fact]
    public void Composition_StopsAtFirstFailure()
    {
        // Arrange
        var result = Result<int>.Success(5);
        var error = new ValidationError("error");

        // Act
        var final = result
            .Map(x => x * 2)
            .Bind(_ => Result<int>.Failure(error))
            .Map(x => x + 5);  // Should not execute

        // Assert
        Assert.False(final.IsSuccess);
        Assert.Contains(error, final.Errors);
    }

    // ========== IMPLICIT OPERATOR TESTS ==========

    [Fact]
    public void ImplicitOperator_ToT_OnSuccess_ReturnsValue()
    {
        // Arrange
        var result = Result<string>.Success("test-value");

        // Act
        string value = result;  // Implicit conversion

        // Assert
        Assert.Equal("test-value", value);
    }

    [Fact]
    public void ImplicitOperator_ToT_OnFailure_ThrowsInvalidOperationException()
    {
        // Arrange
        var result = Result<string>.Failure(new ValidationError("error"));

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            string value = result;  // Implicit conversion should throw
        });
        Assert.Contains("Cannot convert failed Result", ex.Message);
    }

    [Fact]
    public void ImplicitOperator_ToError_OnFailure_ReturnsSingleError()
    {
        // Arrange
        var expectedError = new ValidationError("test error", "field");
        var result = Result<string>.Failure(expectedError);

        // Act
        Error error = result;  // Implicit conversion

        // Assert
        Assert.Same(expectedError, error);
    }

    [Fact]
    public void ImplicitOperator_ToError_OnFailureWithMultipleErrors_ReturnsFirstError()
    {
        // Arrange
        var error1 = new ValidationError("first error", "field1");
        var error2 = new ValidationError("second error", "field2");
        var result = Result<string>.Failure(error1, error2);

        // Act
        Error error = result;  // Implicit conversion

        // Assert
        Assert.Same(error1, error);
    }

    [Fact]
    public void ImplicitOperator_ToError_OnSuccess_ThrowsInvalidOperationException()
    {
        // Arrange
        var result = Result<string>.Success("value");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            Error error = result;  // Implicit conversion should throw
        });
        Assert.Contains("Cannot convert successful Result", ex.Message);
    }

    [Fact]
    public void ImplicitOperator_ToErrorArray_OnFailure_ReturnsAllErrors()
    {
        // Arrange
        var error1 = new ValidationError("error 1");
        var error2 = new ValidationError("error 2");
        var error3 = new DomainError("error 3");
        var result = Result<string>.Failure(error1, error2, error3);

        // Act
        Error[] errors = result;  // Implicit conversion

        // Assert
        Assert.Equal(3, errors.Length);
        Assert.Contains(error1, errors);
        Assert.Contains(error2, errors);
        Assert.Contains(error3, errors);
    }

    [Fact]
    public void ImplicitOperator_ToErrorArray_OnSuccess_ThrowsInvalidOperationException()
    {
        // Arrange
        var result = Result<string>.Success("value");

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            Error[] errors = result;  // Implicit conversion should throw
        });
        Assert.Contains("Cannot convert successful Result", ex.Message);
    }

    [Fact]
    public void ImplicitOperator_SimplerUsagePattern()
    {
        // Arrange
        var result = Result<int>.Success(42);

        // Act & Assert - simpler usage thanks to implicit operators
        if (result.IsSuccess)
        {
            int value = result;  // No need for .Value
            Assert.Equal(42, value);
        }
    }

    [Fact]
    public void ImplicitOperator_ErrorHandlingPattern()
    {
        // Arrange
        var result = Result<int>.Failure(
            new ValidationError("Invalid input"),
            new ValidationError("Missing value")
        );

        // Act & Assert - simpler error handling
        if (!result.IsSuccess)
        {
            Error[] errors = result;  // No need for .Errors.ToArray()
            Assert.Equal(2, errors.Length);
        }
    }
}
