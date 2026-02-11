using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

/// <summary>
/// Builder for SD-JWT VC credential queries.
/// </summary>
public sealed class SdJwtVcCredentialQueryBuilder : CredentialQueryBuilderBase
{
    private List<string>? _vctValues;
    private List<JsonClaimQuery>? _jsonClaims;

    internal SdJwtVcCredentialQueryBuilder(string id) : base(id) { }

    /// <summary>
    /// Sets whether cryptographic holder binding is required.
    /// </summary>
    public new SdJwtVcCredentialQueryBuilder RequireCryptographicHolderBinding(bool require = true)
    {
        base.RequireCryptographicHolderBinding(require);
        return this;
    }

    /// <summary>
    /// Sets whether multiple credentials of this format are allowed.
    /// </summary>
    public new SdJwtVcCredentialQueryBuilder AllowMultiple(bool allow = true)
    {
        base.AllowMultiple(allow);
        return this;
    }

    /// <summary>
    /// Adds a claim set (group of related claim IDs).
    /// </summary>
    public new SdJwtVcCredentialQueryBuilder AddClaimSet(params string[] claimIds)
    {
        base.AddClaimSet(claimIds);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority.
    /// </summary>
    public new SdJwtVcCredentialQueryBuilder AddTrustedAuthority(TrustedAuthority authority)
    {
        base.AddTrustedAuthority(authority);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority by Authority Key Identifier.
    /// </summary>
    public new SdJwtVcCredentialQueryBuilder AddTrustedAuthorityAki(params string[] akiValues)
    {
        base.AddTrustedAuthorityAki(akiValues);
        return this;
    }

    /// <summary>
    /// Adds credential type (vct) values.
    /// </summary>
    public SdJwtVcCredentialQueryBuilder AddVctValues(params string[] vctValues)
    {
        _vctValues ??= [];
        _vctValues.AddRange(vctValues);
        return this;
    }

    /// <summary>
    /// Adds a JSON claim with optional path components.
    /// </summary>
    public SdJwtVcCredentialQueryBuilder AddClaim(string claimId, params string[] path)
    {
        var pathComponents = path.Select(p => new ClaimPathComponent(p)).ToArray();
        return AddClaim(claimId, pathComponents);
    }

    /// <summary>
    /// Adds a JSON claim with path components.
    /// </summary>
    public SdJwtVcCredentialQueryBuilder AddClaim(string claimId, params ClaimPathComponent[] path)
    {
        _jsonClaims ??= [];
        _jsonClaims.Add(new JsonClaimQuery { Id = claimId, Path = new NonEmptyArray<ClaimPathComponent>(path) });
        return this;
    }

    public override DcqlCredentialQuery Build()
    {
        var baseProps = BuildBaseProperties();
        return new SdJwtVcCredentialQuery
        {
            Id = baseProps.Id,
            RequireCryptographicHolderBinding = baseProps.RequireCryptographicHolderBinding,
            Multiple = baseProps.Multiple,
            ClaimSets = baseProps.ClaimSets,
            TrustedAuthorities = baseProps.TrustedAuthorities,
            Meta = _vctValues?.Count > 0 ? new SdJwtVcMeta { VctValues = new NonEmptyArray<string>([.. _vctValues]) } : null,
            Claims = _jsonClaims?.Count > 0 ? new NonEmptyArray<JsonClaimQuery>([.. _jsonClaims]) : null
        };
    }
}
