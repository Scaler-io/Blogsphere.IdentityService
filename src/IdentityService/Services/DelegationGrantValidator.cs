using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityModel;

namespace IdentityService.Services;

public class DelegationGrantValidator(ITokenValidator tokenValidator) : IExtensionGrantValidator
{
    private readonly ITokenValidator _tokenValidator = tokenValidator;
    public string GrantType { get; } = "delegation";

    public async Task ValidateAsync(ExtensionGrantValidationContext context)
    {
        var userToken = context.Request.Raw["token"];
        if (string.IsNullOrEmpty(userToken))
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant);
            return;
        }

        var result = await _tokenValidator.ValidateIdentityTokenAsync(userToken);

        if(result.IsError)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant);
            return;
        }

        var sub = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;
        context.Result = new GrantValidationResult(
            subject: sub,
            authenticationMethod: "delegation",
            claims: result.Claims
        );
    }
}
