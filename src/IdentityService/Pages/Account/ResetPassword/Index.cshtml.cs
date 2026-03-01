using System.Text;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityService.Entities;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Extensions;
using IdentityService.Models;
using IdentityService.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityService.Pages.Account.ResetPassword;

[SecurityHeaders]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public partial class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService,
    SignInManager<ApplicationUser> signInManager,
    SignInManager<ManagementUser> managementSignInManager,
    IPersistedGrantStore persistedGrantStore) : PageModel
{
    private readonly ILogger _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly SignInManager<ManagementUser> _managementSignInManager = managementSignInManager;
    private readonly IPersistedGrantStore _persistedGrantStore = persistedGrantStore;
    public bool IsValidToken { get; set; } = true;

    [BindProperty]
    public InputModel Input { get; set; }

    public async Task<IActionResult> OnGet(
        [FromQuery] string email,
        [FromQuery] string token,
        [FromQuery] string returnUrl = null,
        [FromQuery] string clientId = null,
        [FromQuery] string userType = "blogsphere")
    {
        var effectiveReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, clientId);

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            IsValidToken = false;
            return Page();
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        
        // Determine user store and validate token
        var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
        
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            // Handle ManagementUser token validation
            var managementUser = await _managementUserManager.FindByEmailAsync(email);
            if (managementUser == null)
            {
                IsValidToken = false;
                return Page();
            }

            var result = await _managementUserManager.VerifyUserTokenAsync(
                managementUser, 
                ManagementConstants.ManagementPasswordResetTokenProvider, 
                UserManager<ManagementUser>.ResetPasswordTokenPurpose, 
                decodedToken);
            if (!result)
            {
                IsValidToken = false;
                return Page();
            }
        }
        else
        {
            // Handle ApplicationUser token validation
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                IsValidToken = false;
                return Page();
            }   

            var result = await _userManager.VerifyUserTokenAsync(
                user, 
                Constants.CustomPasswordResetTokenProvider, 
                UserManager<ApplicationUser>.ResetPasswordTokenPurpose, 
                decodedToken);
            if (!result)
            {
                IsValidToken = false;
                return Page();
            }
        }

        TempData["Email"] = email;
        TempData["Token"] = token;
        TempData["UserType"] = userStore;
        TempData["ReturnUrl"] = effectiveReturnUrl;
        TempData["ClientId"] = clientId ?? string.Empty;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var email = TempData["Email"] as string;
        var token = TempData["Token"] as string;
        var returnUrl = TempData["ReturnUrl"] as string;
        var clientId = TempData["ClientId"] as string;
        var effectiveReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, clientId);

        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            return RedirectToPage("/Account/Login/Index", new { returnUrl = effectiveReturnUrl });
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        
        // Determine user store and reset password
        var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
        
        // Add detailed logging for debugging
        _logger.Here().Information("=== RESET PASSWORD DEBUG === Email: {Email}, UserStore: {UserStore}", email, userStore);
        
        if (userStore == ManagementConstants.ManagementUserStore)
        {
            _logger.Here().Information("Processing password reset as MANAGEMENT USER for email: {Email}", email);
            // Handle ManagementUser password reset
            var managementUser = await _managementUserManager.FindByEmailAsync(email);
            if (managementUser == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToPage("/Account/Login/Index", new { returnUrl = effectiveReturnUrl });
            }

            // Verify token explicitly with the specific token provider
            var tokenValid = await _managementUserManager.VerifyUserTokenAsync(
                managementUser, 
                ManagementConstants.ManagementPasswordResetTokenProvider, 
                UserManager<ManagementUser>.ResetPasswordTokenPurpose, 
                decodedToken);
            
            if (!tokenValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired reset token.");
                return Page();
            }

            // Remove password and set new one
            await _managementUserManager.RemovePasswordAsync(managementUser);
            var result = await _managementUserManager.AddPasswordAsync(managementUser, Input.Password);
            
            if (result.Succeeded)
            {
                await RevokeTokensAndSignOutAsync(managementUser.Id, email);
                _logger.Here().Information("Password reset successful for management user {Email}", email);
                return RedirectToPage("/Account/Login/Index", new { returnUrl = effectiveReturnUrl });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        else
        {
            _logger.Here().Information("Processing password reset as APPLICATION USER for email: {Email}", email);
            // Handle ApplicationUser password reset
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToPage("/Account/Login/Index", new { returnUrl = effectiveReturnUrl });
            }

            // Verify token explicitly with the specific token provider
            var tokenValid = await _userManager.VerifyUserTokenAsync(
                user, 
                Constants.CustomPasswordResetTokenProvider, 
                UserManager<ApplicationUser>.ResetPasswordTokenPurpose, 
                decodedToken);
            
            if (!tokenValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired reset token.");
                return Page();
            }

            // Remove password and set new one
            await _userManager.RemovePasswordAsync(user);
            var result = await _userManager.AddPasswordAsync(user, Input.Password);
            
            if (result.Succeeded)
            {
                await RevokeTokensAndSignOutAsync(user.Id, email);
                _logger.Here().Information("Password reset successful for user {Email}", email);
                return RedirectToPage("/Account/Login/Index", new { returnUrl = effectiveReturnUrl });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return Page();
    }

    private async Task RevokeTokensAndSignOutAsync(string subjectId, string email)
    {
        await _persistedGrantStore.RemoveAllAsync(new PersistedGrantFilter
        {
            SubjectId = subjectId
        });

        await _signInManager.SignOutAsync();
        await _managementSignInManager.SignOutAsync();
        await HttpContext.SignOutAsync();
        _logger.Here().Information("Revoked persisted grants and signed out user after password reset for {Email}", email);
    }

}
