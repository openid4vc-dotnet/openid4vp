using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Builders;

public sealed class DcqlQueryBuilder
{
    private readonly List<DcqlCredentialQuery> _credentials = [];
    private readonly List<CredentialSetQuery> _credentialSets = [];

    public static DcqlQueryBuilder Create() => new();

    public DcqlQueryBuilder AddCredential(DcqlCredentialQuery credential)
    {
        _credentials.Add(credential);
        return this;
    }

    public DcqlQueryBuilder AddMdocCredential(string id, Action<MdocCredentialQueryBuilder> configure)
    {
        var builder = new MdocCredentialQueryBuilder(id);
        configure(builder);
        _credentials.Add(builder.Build());
        return this;
    }

    public DcqlQueryBuilder AddW3cVcCredential(string id, Action<W3cVcCredentialQueryBuilder> configure)
    {
        var builder = new W3cVcCredentialQueryBuilder(id);
        configure(builder);
        _credentials.Add(builder.Build());
        return this;
    }

    public DcqlQueryBuilder AddLdpVcCredential(string id, Action<LdpVcCredentialQueryBuilder> configure)
    {
        var builder = new LdpVcCredentialQueryBuilder(id);
        configure(builder);
        _credentials.Add(builder.Build());
        return this;
    }

    public DcqlQueryBuilder AddSdJwtVcCredential(string id, Action<SdJwtVcCredentialQueryBuilder> configure)
    {
        var builder = new SdJwtVcCredentialQueryBuilder(id);
        configure(builder);
        _credentials.Add(builder.Build());
        return this;
    }

    public DcqlQueryBuilder AddDcSdJwtCredential(string id, Action<DcSdJwtCredentialQueryBuilder> configure)
    {
        var builder = new DcSdJwtCredentialQueryBuilder(id);
        configure(builder);
        _credentials.Add(builder.Build());
        return this;
    }

    public DcqlQueryBuilder AddCredentialSet(Action<CredentialSetQueryBuilder> configure)
    {
        var builder = new CredentialSetQueryBuilder();
        configure(builder);
        _credentialSets.Add(builder.Build());
        return this;
    }

    public DcqlQuery Build()
    {
        return new DcqlQuery
        {
            Credentials = new NonEmptyArray<DcqlCredentialQuery>([.._credentials]),
            CredentialSets = _credentialSets.Count > 0 ? new NonEmptyArray<CredentialSetQuery>([.. _credentialSets]) : null
        };
    }
}
