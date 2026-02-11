using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

/// <summary>
/// Builder for mDOC (ISO 18013-5) credential queries.
/// </summary>
public sealed class MdocCredentialQueryBuilder : CredentialQueryBuilderBase
{
    private string? _doctypeValue;
    private List<MdocClaimQuery>? _mdocClaims;

    internal MdocCredentialQueryBuilder(string id) : base(id) { }

    /// <summary>
    /// Sets whether cryptographic holder binding is required.
    /// </summary>
    public new MdocCredentialQueryBuilder RequireCryptographicHolderBinding(bool require = true)
    {
        base.RequireCryptographicHolderBinding(require);
        return this;
    }

    /// <summary>
    /// Sets whether multiple credentials of this format are allowed.
    /// </summary>
    public new MdocCredentialQueryBuilder AllowMultiple(bool allow = true)
    {
        base.AllowMultiple(allow);
        return this;
    }

    /// <summary>
    /// Adds a claim set (group of related claim IDs).
    /// </summary>
    public new MdocCredentialQueryBuilder AddClaimSet(params string[] claimIds)
    {
        base.AddClaimSet(claimIds);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority.
    /// </summary>
    public new MdocCredentialQueryBuilder AddTrustedAuthority(TrustedAuthority authority)
    {
        base.AddTrustedAuthority(authority);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority by Authority Key Identifier.
    /// </summary>
    public new MdocCredentialQueryBuilder AddTrustedAuthorityAki(params string[] akiValues)
    {
        base.AddTrustedAuthorityAki(akiValues);
        return this;
    }

    /// <summary>
    /// Sets the doctype value for the mDOC credential.
    /// </summary>
    public MdocCredentialQueryBuilder WithDoctype(string doctype)
    {
        _doctypeValue = doctype;
        return this;
    }

    /// <summary>
    /// Adds an mDOC claim with namespace and element identifier.
    /// </summary>
    public MdocCredentialQueryBuilder AddMdocClaim(string claimId, string nameSpace, string elementIdentifier, bool? intentToRetain = null)
    {
        _mdocClaims ??= [];
        _mdocClaims.Add(new MdocClaimQuery
        {
            Id = claimId,
            Path = [nameSpace, elementIdentifier],
            IntentToRetain = intentToRetain
        });
        return this;
    }

    public override DcqlCredentialQuery Build()
    {
        var baseProps = BuildBaseProperties();
        return new MdocCredentialQuery
        {
            Id = baseProps.Id,
            RequireCryptographicHolderBinding = baseProps.RequireCryptographicHolderBinding,
            Multiple = baseProps.Multiple,
            ClaimSets = baseProps.ClaimSets,
            TrustedAuthorities = baseProps.TrustedAuthorities,
            Meta = _doctypeValue != null ? new MdocMeta { DoctypeValue = _doctypeValue } : null,
            Claims = _mdocClaims?.Count > 0 ? new NonEmptyArray<MdocClaimQuery>([.. _mdocClaims]) : null
        };
    }
}
