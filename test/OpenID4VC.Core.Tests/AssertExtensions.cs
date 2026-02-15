namespace OpenID4VC.Core.Tests;

using OpenID4VC.Core.Results;

public static class AssertExtensions
{

    public static T AssertSuccess<T>(this Result<T> result)
    {
        Assert.True(result.IsSuccess, $"Expected result to be successful, but it was not. Error: {string.Join(Environment.NewLine, result.Errors.Select(e => e.ToString()))}");
        return result.Value!;
    }

    public static Error[] AssertError<T>(this Result<T> result)
    {
        Assert.False(result.IsSuccess, "Expected result to be an error, but it was successful.");

        return result.Errors.ToArray();
    }
}
