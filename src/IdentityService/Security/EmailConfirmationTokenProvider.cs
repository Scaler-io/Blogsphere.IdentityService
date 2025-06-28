using IdentityService.Entities;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityService.Security;

public class EmailConfirmationTokenProviderOptions : DataProtectionTokenProviderOptions
{
}

public class EmailConfirmationTokenProvider<TUser>(
    IDataProtectionProvider dataProtectionProvider, 
    IOptions<EmailConfirmationTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<TUser>> logger
    ) : DataProtectorTokenProvider<TUser>(dataProtectionProvider, options, logger)
    where TUser : ApplicationUser
{
}
