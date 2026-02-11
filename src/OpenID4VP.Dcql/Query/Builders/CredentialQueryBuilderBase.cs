using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

/// <summary>
/// Base class for credential query builders.
/// Provides common properties and methods shared across all credential format builders.
/// </summary>
public abstract class CredentialQueryBuilderBase
{
    protected string Id { get; }
    private bool _requireCryptographicHolderBinding = true;
    private bool _multiple = false;
    protected List<NonEmptyArray<string>>? ClaimSets { get; set; }
    protected List<TrustedAuthority>? TrustedAuthorities { get; set; }

    protected CredentialQueryBuilderBase(string id) => Id = id;

    /// <summary>
    /// Sets whether cryptographic holder binding is required.
    /// </summary>
    public CredentialQueryBuilderBase RequireCryptographicHolderBinding(bool require = true)
    {
        _requireCryptographicHolderBinding = require;
        return this;
    }

    /// <summary>
    /// Sets whether multiple credentials of this format are allowed.
    /// </summary>
    public CredentialQueryBuilderBase AllowMultiple(bool allow = true)
    {
        _multiple = allow;
        return this;
    }

    /// <summary>
    /// Adds a claim set (group of related claim IDs).
    /// </summary>
    public CredentialQueryBuilderBase AddClaimSet(params string[] claimIds)
    {
        ClaimSets ??= [];
        ClaimSets.Add(new NonEmptyArray<string>(claimIds));
        return this;
    }

    /// <summary>
    /// Adds a trusted authority.
    /// </summary>
    public CredentialQueryBuilderBase AddTrustedAuthority(TrustedAuthority authority)
    {
        TrustedAuthorities ??= [];
        TrustedAuthorities.Add(authority);
        return this;
    }

    /// <summary>
    /// Adds a trusted authority by Authority Key Identifier.
    /// </summary>
    public CredentialQueryBuilderBase AddTrustedAuthorityAki(params string[] akiValues)
    {
        return AddTrustedAuthority(new AuthorityKeyIdentifierTrustAuthority { Values = new NonEmptyArray<string>(akiValues) });
    }

    /// <summary>
    /// Builds the base properties common to all credential query types.
    /// </summary>
    protected (string Id, bool RequireCryptographicHolderBinding, bool Multiple,
             NonEmptyArray<NonEmptyArray<string>>? ClaimSets, NonEmptyArray<TrustedAuthority>? TrustedAuthorities)
        BuildBaseProperties()
    {
        return (
            Id: Id,
            RequireCryptographicHolderBinding: _requireCryptographicHolderBinding,
            Multiple: _multiple,
            ClaimSets: ClaimSets?.Count > 0 ? new NonEmptyArray<NonEmptyArray<string>>([.. ClaimSets]) : null,
            TrustedAuthorities: TrustedAuthorities?.Count > 0 ? new NonEmptyArray<TrustedAuthority>([.. TrustedAuthorities]) : null
        );
    }

    /// <summary>
    /// Builds the final credential query.
    /// </summary>
    public abstract DcqlCredentialQuery Build();
}
