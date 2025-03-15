using IdentityService.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityService.Security;

public class EmailConfirmationTokenProvider<TUser> : DataProtectorTokenProvider<TUser>
    where TUser : ApplicationUser
{
    public EmailConfirmationTokenProvider(
        IDataProtectionProvider dataProtectionProvider, IOptions<DataProtectionTokenProviderOptions> options,
        ILogger<DataProtectorTokenProvider<TUser>> logger
    ) : base(dataProtectionProvider, options, logger)
    {
        options.Value.TokenLifespan = TimeSpan.FromSeconds(3600);
    }
}
