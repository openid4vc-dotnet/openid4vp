namespace OpenID4VP.Builders;

using OpenID4VC.Core.Results;

internal static class BuilderErrors
{
    public static Error ClientIdIsRequired() 
        => new ValidationError("client_id is required", "ClientId");

    public static Error ResponseModeIsRequired() 
        => new ValidationError("response_mode is required", "ResponseMode");
}
