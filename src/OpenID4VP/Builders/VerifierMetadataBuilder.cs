using System.Text.Json;
using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for creating VerifierMetadata objects.
/// </summary>
public sealed class VerifierMetadataBuilder
{
    private JsonElement? _jwks;
    private List<string>? _encryptedResponseEncValues;
    private JsonElement? _vpFormatsSupported;
    private Dictionary<string, JsonElement>? _extensionData;

    public static VerifierMetadataBuilder Create() => new();

    public VerifierMetadataBuilder WithJwks(JsonElement jwks)
    {
        _jwks = jwks;
        return this;
    }

    public VerifierMetadataBuilder AddEncryptedResponseEncValue(string encAlgorithm)
    {
        if (string.IsNullOrWhiteSpace(encAlgorithm))
            throw new ArgumentException("Encryption algorithm cannot be null or empty", nameof(encAlgorithm));

        _encryptedResponseEncValues ??= [];
        _encryptedResponseEncValues.Add(encAlgorithm);
        return this;
    }

    public VerifierMetadataBuilder WithVpFormatsSupported(JsonElement vpFormatsSupported)
    {
        _vpFormatsSupported = vpFormatsSupported;
        return this;
    }

    public VerifierMetadata Build()
    {
        return new VerifierMetadata
        {
            Jwks = _jwks,
            EncryptedResponseEncValuesSupported = _encryptedResponseEncValues?.AsReadOnly(),
            VpFormatsSupported = _vpFormatsSupported,
            ExtensionData = _extensionData
        };
    }
}
