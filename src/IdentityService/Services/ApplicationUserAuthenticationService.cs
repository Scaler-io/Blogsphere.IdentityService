using Duende.IdentityServer.Services;
using IdentityService.Entities;
using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Services;

public interface IApplicationUserAuthenticationService : IBaseAuthenticationService<ApplicationUser>
{
}

public class ApplicationUserAuthenticationService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IEventService events,
    IPublishService publishService,
    ILogger logger) : BaseAuthenticationService<ApplicationUser>(userManager, signInManager, events, publishService, logger, 
           "blogsphere", 
           Constants.CustomTwoFactorTokenProvider, 
           Constants.CustomPasswordResetTokenProvider), IApplicationUserAuthenticationService
{
    protected override string GetUserDisplayName(ApplicationUser user)
    {
        return user.FullName ?? user.UserName ?? user.Email ?? "Unknown";
    }
} 