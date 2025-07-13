using IdentityService.Management.Entities;
using IdentityService.Extensions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityService.Management.Security;

public class ManagementEmailConfirmationTokenProviderOptions : DataProtectionTokenProviderOptions
{
}

public class ManagementEmailConfirmationTokenProvider<TUser>(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<ManagementEmailConfirmationTokenProviderOptions> options,
    Microsoft.Extensions.Logging.ILogger<DataProtectorTokenProvider<TUser>> msLogger,
    ILogger logger
) : DataProtectorTokenProvider<TUser>(dataProtectionProvider, options, msLogger)
    where TUser : ManagementUser
{
    private readonly ILogger _logger = logger;

    public override async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
    {
        _logger.Here().Information("Generating email confirmation token for management user {UserId}", user.Id);
        return await base.GenerateAsync(purpose, manager, user);
    }

    public override async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
    {
        try
        {
            var isValid = await base.ValidateAsync(purpose, token, manager, user);
            _logger.Here().Information("Email confirmation token validation result for management user {UserId}: {IsValid}", user.Id, isValid);
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error validating email confirmation token for management user {UserId}", user.Id);
            return false;
        }
    }
} 