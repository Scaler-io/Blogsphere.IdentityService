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

    public static IEnumerable<ApiScope> ApiScopes => [
        new("apigateway:read"),
        new("apigateway:write"),
        new("apigateway:delete"),
    ];

    public static IEnumerable<ApiResource> ApiResources => [
        new("blogsphere.api.gateway", "Blogsphere API Gateway")
        {
            Scopes =
            {
                "apigateway:read",
                "apigateway:write",
                "apigateway:delete",
            }
        }
    ];

    public static IEnumerable<Client> Clients => [
        new()
        {
            ClientId = "postman",
            ClientName = "Postman",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
            RedirectUris = { "https://www.getpostmane.com/oauth2/callback" }, // Not going to be used. nore redirection in postman testing 
            ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },
            AllowedScopes =
            {
                "openid",
                "profile",
                "email",
                "apigateway:read",
                "apigateway:write",
                "apigateway:delete",
            },
            RequireClientSecret = true,
            AccessTokenType = AccessTokenType.Jwt,
        },
        new()
        {
            ClientId = "postman2",
            ClientName = "Postman2",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
            RedirectUris = { "https://www.getpostmane.com/oauth2/callback" }, // Not going to be used. nore redirection in postman testing 
            ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },
            AllowedScopes =
            {
                "openid",
                "profile",
                "email",
                "apigateway:read",
                "apigateway:write",
                "apigateway:delete",
            },
            RequireClientSecret = true,
            AccessTokenType = AccessTokenType.Jwt,
        },
        new()
        {
            ClientId = "blogsphere-management",
            ClientName = "Blogsphere Management Application",
            AllowedGrantTypes = GrantTypes.Code,
            RedirectUris = { "http://localhost:4200" },
            PostLogoutRedirectUris = { "http://localhost:4200" },
            ClientSecrets = { new Secret("management-secret-key-2024".Sha256()) },
            AllowedScopes =
            {
                "openid",
                "profile",
                "email",
                "apigateway:read",
                "apigateway:write",
                "apigateway:delete"
            },
            RequireClientSecret = false,
            RequirePkce = true,
            AccessTokenType = AccessTokenType.Jwt,
            AllowOfflineAccess = true,
            AccessTokenLifetime = 3600*24*7,
            AuthorizationCodeLifetime = 3600*24, //
            AlwaysIncludeUserClaimsInIdToken = true,
        },
    ];
}
