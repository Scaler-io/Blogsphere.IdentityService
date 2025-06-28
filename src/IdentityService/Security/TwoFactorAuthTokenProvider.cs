using System.Security.Cryptography;
using IdentityService.Entities;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Security;

public class TwoFactorAuthTokenProvider :  IUserTwoFactorTokenProvider<ApplicationUser>
{
    public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        return Task.FromResult(true);
    }

    public Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
        return Task.FromResult(code);
    }

    public async Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        var expectedCode = await manager.GetAuthenticationTokenAsync(user, "2Fa", "2FACode");
        var expiryString = await manager.GetAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");
        if(!DateTime.TryParse(expiryString, out var expiry) || DateTime.UtcNow > expiry)
            return false;
        return expectedCode == token;
    }
}
