using System.Security.Cryptography;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Security;

public abstract class BaseTwoFactorTokenProvider<TUser>(ILogger logger, string userType) : IUserTwoFactorTokenProvider<TUser>
    where TUser : IdentityUser
{
    protected readonly ILogger _logger = logger;
    protected readonly string _userType = userType;

    public virtual async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        var isTwoFactorEnabled = await manager.GetTwoFactorEnabledAsync(user);
        _logger.Here().Information("Checking if 2FA token can be generated for {UserType} user {UserId}: {IsEnabled}", _userType, user.Id, isTwoFactorEnabled);
        return isTwoFactorEnabled;
    }

    public virtual Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
        _logger.Here().Information("Generated 2FA token for {UserType} user {UserId}", _userType, user.Id);
        return Task.FromResult(code);
    }

    public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        try
        {
            var expectedCode = await manager.GetAuthenticationTokenAsync(user, "2Fa", "2FACode");
            var expiryString = await manager.GetAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");
            
            if (!DateTime.TryParse(expiryString, out var expiry) || DateTime.UtcNow > expiry)
            {
                _logger.Here().Warning("2FA token expired for {UserType} user {UserId}", _userType, user.Id);
                return false;
            }

            var isValid = expectedCode == token;
            _logger.Here().Information("2FA token validation result for {UserType} user {UserId}: {IsValid}", _userType, user.Id, isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error validating 2FA token for {UserType} user {UserId}", _userType, user.Id);
            return false;
        }
    }
} 