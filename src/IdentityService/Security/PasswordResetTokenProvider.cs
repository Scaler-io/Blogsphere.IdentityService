using IdentityService.Entities;
using IdentityService.Extensions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityService.Security;

public class PasswordResetTokenProviderOptions : DataProtectionTokenProviderOptions
{
}

public class PasswordResetTokenProvider<TUser>(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<PasswordResetTokenProviderOptions> options,
    Microsoft.Extensions.Logging.ILogger<DataProtectorTokenProvider<TUser>> msLogger,
    ILogger logger
) : DataProtectorTokenProvider<TUser>(dataProtectionProvider, options, msLogger)
    where TUser : ApplicationUser
{
    private readonly ILogger _logger = logger;

    public override async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        _logger.Here().Information("Generating password reset token for application user {UserId}", user.Id);
        return await base.GenerateAsync(purpose, manager, user);
    }

    public override async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        try
        {
            var isValid = await base.ValidateAsync(purpose, token, manager, user);
            _logger.Here().Information("Password reset token validation result for application user {UserId}: {IsValid}", user.Id, isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error validating password reset token for application user {UserId}", user.Id);
            return false;
        }
    }
}
