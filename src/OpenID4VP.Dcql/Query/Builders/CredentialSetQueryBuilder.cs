using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

public sealed class CredentialSetQueryBuilder
{
    private readonly List<string[]> _options = [];
    private bool _required = true;

    public CredentialSetQueryBuilder Required(bool required = true)
    {
        _required = required;
        return this;
    }

    public CredentialSetQueryBuilder AddOption(params string[] credentialIds)
    {
        _options.Add(credentialIds);
        return this;
    }

    public CredentialSetQuery Build()
    {
        return new CredentialSetQuery
        {
            Options = new NonEmptyArray<string[]>(_options.ToArray()),
            Required = _required
        };
    }
}
