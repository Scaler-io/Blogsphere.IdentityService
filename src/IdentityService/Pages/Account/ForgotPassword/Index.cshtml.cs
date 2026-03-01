using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using IdentityService.Entities;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Models;
using System.ComponentModel.DataAnnotations;
using IdentityService.Extensions;
using IdentityService.Services;
using IdentityService.Security;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Contracts.Events;

namespace IdentityService.Pages.Account.ForgotPassword;

[SecurityHeaders]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public class Index(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    UserManager<ManagementUser> managementUserManager,
    IMultiUserStoreService multiUserStoreService,
    IPublishService publishService) : PageModel
{
    private readonly ILogger _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly IPublishService _publishService = publishService;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter a valid email address")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        public string Email { get; set; }
    }

    [BindProperty]
    public InputModel Input { get; set; }

    [BindProperty(SupportsGet = true)]
    public string ReturnUrl { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string ClientId { get; set; } = string.Empty;

    [TempData]
    public string StatusMessage { get; set; }

    public IActionResult OnGet([FromQuery] string email = null, [FromQuery] string returnUrl = null, [FromQuery] string clientId = null)
    {
        // If user is authenticated, redirect to home
        if (User.IsAuthenticated())
        {
            return RedirectToPage("/Index");
        }

        ClientId = clientId ?? string.Empty;
        ReturnUrl = ReturnUrlGuard.NormalizeForClientApp(returnUrl, ClientId);
        Input ??= new InputModel();
        Input.Email = (email ?? string.Empty).Trim();

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        ReturnUrl = ReturnUrlGuard.NormalizeForClientApp(ReturnUrl, ClientId);
        try
        {
            if (Input?.Email == null)
            {
                return HandleError("Please enter a valid email address");
            }
            
            if (!ModelState.IsValid)
            {
                return HandleValidationErrors();
            }

            var email = Input.Email.Trim().ToLowerInvariant();
            
            // Determine which user store to use based on email
            var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
            
            // Add detailed logging for debugging
            _logger.Here().Information("=== FORGOT PASSWORD DEBUG === Email: {Email}, UserStore: {UserStore}", email, userStore);
            
            if (userStore == ManagementConstants.ManagementUserStore)
            {
                _logger.Here().Information("Processing as MANAGEMENT USER for email: {Email}", email);
                // Handle ManagementUser password reset
                var managementUser = await _managementUserManager.FindByEmailAsync(email);
                
                if (managementUser != null && await _managementUserManager.IsEmailConfirmedAsync(managementUser))
                {
                    // Check if user is locked out
                    if (!await _managementUserManager.IsLockedOutAsync(managementUser))
                    {
                        // Generate password reset token using the specific token provider
                        var code = await _managementUserManager.GenerateUserTokenAsync(
                            managementUser, 
                            ManagementConstants.ManagementPasswordResetTokenProvider, 
                            UserManager<ManagementUser>.ResetPasswordTokenPurpose);
                        
                        await _publishService.PublishAsync<PasswordResetInstructionSent>(new()
                        {
                            Email = email,
                        }, Guid.NewGuid().ToString(), new
                        {
                            Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code)),
                            UserType = "management",
                            ReturnUrl,
                            ClientId
                        });
                        
                        _logger.Here().Information("Password reset token generated for management user: {Email}", email);
                    }
                    else
                    {
                        _logger.Here().Warning("Password reset attempted for locked out management account: {Email}", email);
                    }
                }
                else
                {
                    // User doesn't exist or email not confirmed - log but don't reveal this info
                    _logger.Here().Warning("Password reset attempted for invalid or unconfirmed management email: {Email}", email);
                }
            }
            else
            {
                _logger.Here().Information("Processing as APPLICATION USER for email: {Email}", email);
                // Handle ApplicationUser password reset
                var user = await _userManager.FindByEmailAsync(email);
                
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    // Check if user is locked out
                    if (!await _userManager.IsLockedOutAsync(user))
                    {
                        // Generate password reset token using the specific token provider
                        var code = await _userManager.GenerateUserTokenAsync(
                            user, 
                            Constants.CustomPasswordResetTokenProvider, 
                            UserManager<ApplicationUser>.ResetPasswordTokenPurpose);
                        
                        await _publishService.PublishAsync<PasswordResetInstructionSent>(new()
                        {
                            Email = email,
                        }, Guid.NewGuid().ToString(), new
                        {
                            Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code)),
                            UserType = "blogsphere",
                            ReturnUrl,
                            ClientId
                        });
                        
                        _logger.Here().Information("Password reset token generated for blogsphere user: {Email}", email);
                    }
                    else
                    {
                        _logger.Here().Warning("Password reset attempted for locked out account: {Email}", email);
                    }
                }
                else
                {
                    // User doesn't exist or email not confirmed - log but don't reveal this info
                    _logger.Here().Warning("Password reset attempted for invalid or unconfirmed email: {Email}", email);
                }
            }
          
            // Always redirect to status page for security (don't reveal if user exists or not)
            return RedirectToPage("/Account/ForgotPassword/Status");
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error in password reset for \"{Email}\"", Input?.Email);
            return HandleError("An error occurred while processing your request. Please try again later.");
        }
    }

    private IActionResult HandleError(string message)
    {
        if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
        {
            return new JsonResult(new
            {
                success = false,
                message = message
            });
        }

        ModelState.AddModelError("Input.Email", message);
        return Page();
    }

    private IActionResult HandleValidationErrors()
    {
        if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
        {
            return new JsonResult(new
            {
                success = false,
                errors = ModelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                )
            });
        }

        return Page();
    }
}
