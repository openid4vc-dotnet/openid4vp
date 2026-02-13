namespace OpenID4VP.Builders;

using OpenID4VC.Core.Results;

/// <summary>
/// Factory for creating builder validation errors with consistent codes and messages.
/// Used by AuthorizationRequestBuilder to accumulate validation failures.
/// </summary>
internal static class BuilderErrors
{
    public static Error ClientIdIsRequired() 
        => new ValidationError("client_id is required", "ClientId");

    public static Error ResponseModeIsRequired() 
        => new ValidationError("response_mode is required", "ResponseMode");

    public static Error ResponseTypeIsRequired()
        => new ValidationError("response_type is required", "ResponseType");

    public static Error NonceIsRequired()
        => new ValidationError("nonce is required", "Nonce");

    public static Error DcqlCanOnlyBeSetOnce()
        => new ValidationError("DCQL query can only be configured once", "DcqlQuery");

    public static Error DcqlConfigureCannotBeNull()
        => new ValidationError("DCQL configure action cannot be null", "DcqlConfigure");

    public static Error VerifierAttestationCannotBeNull()
        => new ValidationError("Verifier attestation cannot be null", "VerifierAttestation");

    public static Error TransactionDataCannotBeNull()
        => new ValidationError("Transaction data cannot be null or empty", "TransactionData");
}
