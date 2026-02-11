using System.Text.Json;
using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for creating VerifierAttestation objects.
/// </summary>
public sealed class VerifierAttestationBuilder
{
    private string? _format;
    private JsonElement? _data;
    private List<string>? _credentialIds;

    public static VerifierAttestationBuilder Create() => new();

    public VerifierAttestationBuilder WithFormat(string format)
    {
        if (string.IsNullOrWhiteSpace(format))
            throw new ArgumentException("Format cannot be null or empty", nameof(format));

        _format = format;
        return this;
    }

    public VerifierAttestationBuilder WithData(JsonElement data)
    {
        _data = data;
        return this;
    }

    public VerifierAttestationBuilder AddCredentialId(string credentialId)
    {
        if (string.IsNullOrWhiteSpace(credentialId))
            throw new ArgumentException("Credential ID cannot be null or empty", nameof(credentialId));

        _credentialIds ??= [];
        _credentialIds.Add(credentialId);
        return this;
    }

    public VerifierAttestation Build()
    {
        if (string.IsNullOrEmpty(_format))
            throw new InvalidOperationException("Format is required");

        return new VerifierAttestation
        {
            Format = _format,
            Data = _data ?? default,
            CredentialIds = _credentialIds?.AsReadOnly()
        };
    }
}
