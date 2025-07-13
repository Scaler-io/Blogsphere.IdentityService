using Duende.IdentityServer.Services;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Services;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Management.Services;

public interface IManagementUserAuthenticationService : IBaseAuthenticationService<ManagementUser>
{
}

public class ManagementUserAuthenticationService(
    UserManager<ManagementUser> userManager,
    SignInManager<ManagementUser> signInManager,
    IEventService events,
    IPublishService publishService,
    ILogger logger) : BaseAuthenticationService<ManagementUser>(userManager, signInManager, events, publishService, logger, 
           "management", 
           ManagementConstants.ManagementTwoFactorTokenProvider, 
           ManagementConstants.ManagementPasswordResetTokenProvider), IManagementUserAuthenticationService
{
    protected override string GetUserDisplayName(ManagementUser user)
    {
        return user.FullName ?? user.UserName ?? user.Email ?? "Unknown";
    }
} 