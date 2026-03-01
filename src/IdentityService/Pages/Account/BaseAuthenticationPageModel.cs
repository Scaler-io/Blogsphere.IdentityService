using Duende.IdentityServer.Services;
using IdentityService.Extensions;
using IdentityService.Management.Services;
using IdentityService.Security;
using IdentityService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account;

[SecurityHeaders]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public abstract class BaseAuthenticationPageModel(
    ILogger logger,
    IMultiUserStoreService multiUserStoreService,
    IIdentityServerInteractionService interaction,
    IApplicationUserAuthenticationService applicationUserAuthService,
    IManagementUserAuthenticationService managementUserAuthService) : PageModel
{
    protected readonly ILogger _logger = logger;
    protected readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    protected readonly IIdentityServerInteractionService _interaction = interaction;
    protected readonly IApplicationUserAuthenticationService _applicationUserAuthService = applicationUserAuthService;
    protected readonly IManagementUserAuthenticationService _managementUserAuthService = managementUserAuthService;

    protected async Task<IBaseAuthenticationService<Microsoft.AspNetCore.Identity.IdentityUser>> GetAuthenticationServiceAsync(string email)
    {
        var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
        
        if (userStore == IdentityService.Management.Models.ManagementConstants.ManagementUserStore)
        {
            return (IBaseAuthenticationService<Microsoft.AspNetCore.Identity.IdentityUser>)_managementUserAuthService;
        }
        
        return (IBaseAuthenticationService<Microsoft.AspNetCore.Identity.IdentityUser>)_applicationUserAuthService;
    }

    protected void SetTempDataForTwoFactor(string userEmail, string returnUrl, bool rememberLogin, string userType)
    {
        TempData["2FA_UserEmail"] = userEmail;
        TempData["2FA_ReturnUrl"] = ReturnUrlGuard.NormalizeForIdentityFlow(returnUrl);
        TempData["2FA_RemberMe"] = rememberLogin;
        TempData["2FA_UserType"] = userType;
    }

    protected (string email, string returnUrl, bool rememberLogin, string userType) GetTempDataForTwoFactor()
    {
        var userEmail = TempData["2FA_UserEmail"] as string ?? "";
        var returnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(TempData["2FA_ReturnUrl"] as string);
        var rememberMe = TempData["2FA_RemberMe"] as bool? ?? false;
        var userType = TempData["2FA_UserType"] as string ?? "blogsphere";

        return (userEmail, returnUrl, rememberMe, userType);
    }

    protected void SetTempDataForPasswordReset(string email, string token, string userType)
    {
        TempData["Email"] = email;
        TempData["Token"] = token;
        TempData["UserType"] = userType;
    }

    protected (string email, string token, string userType) GetTempDataForPasswordReset()
    {
        var email = TempData["Email"] as string ?? "";
        var token = TempData["Token"] as string ?? "";
        var userType = TempData["UserType"] as string ?? "blogsphere";

        return (email, token, userType);
    }

    protected void LogAuthenticationEvent(string eventType, string email, string userType, string additionalInfo = null)
    {
        _logger.Here().Information("=== {EventType} === Email: {Email}, UserType: {UserType}{AdditionalInfo}", 
            eventType, email, userType, additionalInfo != null ? $", {additionalInfo}" : "");
    }
} 