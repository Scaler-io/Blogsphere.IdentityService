using System.Text;
using IdentityService.Entities;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Extensions;
using IdentityService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityService.Pages.Account.ResetPassword;

[SecurityHeaders]
[AllowAnonymous]
public partial class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService) : PageModel
{
    private readonly ILogger _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    public bool IsValidToken { get; set; } = true;

    [BindProperty]
    public InputModel Input { get; set; }

    public async Task<IActionResult> OnGet([FromQuery] string email, [FromQuery] string token, [FromQuery] string userType = "blogsphere")
    {
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
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var email = TempData["Email"] as string;
        var token = TempData["Token"] as string;
        var userType = TempData["UserType"] as string ?? "blogsphere";

        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            return RedirectToPage("/Account/Login/Index");
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
                return RedirectToPage("/Account/Login/Index");
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
                _logger.Here().Information("Password reset successful for management user {Email}", email);
                return RedirectToPage("/Account/Login/Index");
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
                return RedirectToPage("/Account/Login/Index");
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
                _logger.Here().Information("Password reset successful for user {Email}", email);
                return RedirectToPage("/Account/Login/Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return Page();
    }
}
