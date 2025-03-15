using Duende.IdentityServer.Models;

namespace IdentityService;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        [
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email()
        ];

    public static IEnumerable<ApiScope> ApiScopes => [];

    public static IEnumerable<ApiResource> ApiResources => [];

    public static IEnumerable<Client> Clients => [
        new()
        {
            ClientId = "postman",
            ClientName = "Postman",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
            RedirectUris = { "https://www.getpostmane.com/oauth2/callback" }, // Not going to be used. nore redirection in postman testing 
            ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },
            AllowedScopes =
            {
                "openid",
                "profile",
                "email"
            },
            RequireClientSecret = true,
            AccessTokenType = AccessTokenType.Jwt,
        },
    ];
}
