using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

/// <summary>
/// Builder for Linked Data Proof Verifiable Credentials credential queries.
/// </summary>
public sealed class LdpVcCredentialQueryBuilder : CredentialQueryBuilderBase
{
    private List<NonEmptyArray<string>>? _typeValues;
    private List<JsonClaimQuery>? _jsonClaims;

    internal LdpVcCredentialQueryBuilder(string id) : base(id) { }

    /// <summary>
    /// Sets whether cryptographic holder binding is required.
    /// </summary>
    public new LdpVcCredentialQueryBuilder RequireCryptographicHolderBinding(bool require = true)
    {
        base.RequireCryptographicHolderBinding(require);
        return this;
    }

    /// <summary>
    /// Sets whether multiple credentials of this format are allowed.
    /// </summary>
    public new LdpVcCredentialQueryBuilder AllowMultiple(bool allow = true)
    {
        base.AllowMultiple(allow);
        return this;
    }

    /// <summary>
    /// Adds a claim set (group of related claim IDs).
    /// </summary>
    public new LdpVcCredentialQueryBuilder AddClaimSet(params string[] claimIds)
    {
        base.AddClaimSet(claimIds);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority.
    /// </summary>
    public new LdpVcCredentialQueryBuilder AddTrustedAuthority(TrustedAuthority authority)
    {
        base.AddTrustedAuthority(authority);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority by Authority Key Identifier.
    /// </summary>
    public new LdpVcCredentialQueryBuilder AddTrustedAuthorityAki(params string[] akiValues)
    {
        base.AddTrustedAuthorityAki(akiValues);
        return this;
    }

    /// <summary>
    /// Adds credential type values.
    /// </summary>
    public LdpVcCredentialQueryBuilder AddTypeValues(params string[] types)
    {
        _typeValues ??= [];
        _typeValues.Add(new NonEmptyArray<string>(types));
        return this;
    }

    /// <summary>
    /// Adds a JSON claim with optional path components.
    /// </summary>
    public LdpVcCredentialQueryBuilder AddClaim(string claimId, params string[] path)
    {
        var pathComponents = path.Select(p => new ClaimPathComponent(p)).ToArray();
        return AddClaim(claimId, pathComponents);
    }

    /// <summary>
    /// Adds a JSON claim with path components.
    /// </summary>
    public LdpVcCredentialQueryBuilder AddClaim(string claimId, params ClaimPathComponent[] path)
    {
        _jsonClaims ??= [];
        _jsonClaims.Add(new JsonClaimQuery { Id = claimId, Path = new NonEmptyArray<ClaimPathComponent>(path) });
        return this;
    }

    public override DcqlCredentialQuery Build()
    {
        if (_typeValues is null or { Count: 0 })
        {
            throw new InvalidOperationException(
                "LdpVcCredentialQuery requires at least one type value. Use AddTypeValues() to specify the credential types.");
        }

        var baseProps = BuildBaseProperties();
        return new LdpVcCredentialQuery
        {
            Id = baseProps.Id,
            RequireCryptographicHolderBinding = baseProps.RequireCryptographicHolderBinding,
            Multiple = baseProps.Multiple,
            ClaimSets = baseProps.ClaimSets,
            TrustedAuthorities = baseProps.TrustedAuthorities,
            Meta = new W3cVcMeta { TypeValues = new NonEmptyArray<NonEmptyArray<string>>([.. _typeValues]) },
            Claims = _jsonClaims?.Count > 0 ? new NonEmptyArray<JsonClaimQuery>([.. _jsonClaims]) : null
        };
    }
}
