using IdentityService.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Serilog;
using IdentityService.Extensions;

namespace IdentityService.Security;

public class PasswordResetTokenProviderOptions : DataProtectionTokenProviderOptions
{
}

public class PasswordResetTokenProvider<TUser>(IDataProtectionProvider dataProtectionProvider,
    IOptions<PasswordResetTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<TUser>> logger
) : DataProtectorTokenProvider<TUser>(dataProtectionProvider, options, logger)
    where TUser : ApplicationUser
{
    private readonly ILogger _logger = Log.ForContext<PasswordResetTokenProvider<TUser>>();

    public override async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        try
        {
            // Let the base implementation handle all token validation including expiration
            var isValid = await base.ValidateAsync(purpose, token, manager, user);
            _logger.Here().Information("Password reset token validation result: {IsValid}", isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error validating password reset token");
            return false;
        }
    }
}
