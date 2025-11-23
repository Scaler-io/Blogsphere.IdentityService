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
        new("userapi:read"),
        new("userapi:write"),
    ];

    public static IEnumerable<ApiResource> ApiResources => [
        new("blogsphere.apigateway.api", "Blogsphere API Gateway")
        {
            Scopes =
            {
                "apigateway:read",
                "apigateway:write",
                "apigateway:delete",
            }
        },
        new("blogsphere.user.api", "Blogsphere User API")
        {
            Scopes =
            {
                "userapi:read",
                "userapi:write",
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
                "userapi:read",
                "userapi:write",
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
                "apigateway:delete",
                "offline_access"  // ← CRITICAL: Add this
            },
            RequireClientSecret = false,
            RequirePkce = true,
            AccessTokenType = AccessTokenType.Jwt,
            AllowOfflineAccess = true,          
            // Token lifetimes
            AccessTokenLifetime = 3600 * 24 * 7,        // 7 days
            IdentityTokenLifetime = 3600,                // 1 hour 
            AuthorizationCodeLifetime = 300,             // 5 minutes
            
            // Refresh token settings
            RefreshTokenUsage = TokenUsage.ReUse,
            RefreshTokenExpiration = TokenExpiration.Sliding,
            SlidingRefreshTokenLifetime = 3600 * 24 * 30, // 30 days
            
            AlwaysIncludeUserClaimsInIdToken = true,
        },
        new()
        {
            ClientId = "blogsphere.apigateway.api",
            ClientName = "Blogsphere API Gateway",
            ClientSecrets = { new Secret("apigateway-secret-key-2024".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes =
            {
                "apigateway:read"
            },
            AccessTokenType = AccessTokenType.Jwt,
            AccessTokenLifetime = 3600*60,
            AlwaysIncludeUserClaimsInIdToken = false,
        },
        new()
        {
            ClientId = "blogshere.user.api",
            ClientName = "Blogsphere User API",
            ClientSecrets = { new Secret("user-secret-key-2024".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes =
            {
                "userapi:read"
            },
            AccessTokenType = AccessTokenType.Jwt,
            AccessTokenLifetime = 3600*60,
            AlwaysIncludeUserClaimsInIdToken = false,
        },
        new()
        {
            ClientId = "blogsphere.bff.api",
            ClientName = "Blogsphere BFF API",
            ClientSecrets = { new Secret("bff-secret-key-2024".Sha256()) },
            AllowedGrantTypes = { "delegation", GrantType.ClientCredentials },
            AllowedScopes = { "apigateway:read", "userapi:read" }
        }
    ];
}
