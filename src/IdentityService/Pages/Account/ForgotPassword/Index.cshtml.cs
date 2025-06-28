using Duende.IdentityServer.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using IdentityService.Entities;
using System.ComponentModel.DataAnnotations;
using IdentityService.Extensions;
using IdentityService.Services;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Contracts.Events;

namespace IdentityService.Pages.Account.ForgotPassword;

[SecurityHeaders]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public class Index : PageModel
{
    private readonly ILogger _logger;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPublishService _publishService;

    public class InputModel
    {
        [Required(ErrorMessage = "Please enter a valid email address")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        public string Email { get; set; }
    }

    [BindProperty]
    public InputModel Input { get; set; }

    [TempData]
    public string StatusMessage { get; set; }


    public Index(
        ILogger logger,
        UserManager<ApplicationUser> userManager,
        IPublishService publishService)
    {
        _logger = logger;
        _userManager = userManager;
        _publishService = publishService;
    }

    public IActionResult OnGet()
    {
        // If user is authenticated, redirect to home
        if (User.IsAuthenticated())
        {
            return RedirectToPage("/Index");
        }

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
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
            
            // Find user by email
            var user = await _userManager.FindByEmailAsync(email);
            
            if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
            {
                // Don't reveal that the user does not exist or is not confirmed
                _logger.Here().Warning("Password reset attempted for invalid email: {Email}", email);
                return HandleError("Please enter a valid email address");
            }

            // Check if user is locked out
            if (await _userManager.IsLockedOutAsync(user))
            {
                // Don't reveal the lockout to potential attackers
                _logger.Here().Warning("Password reset attempted for locked out account: {Email}", email);
                return HandleError("Please enter a valid email address");
            }

            // Generate password reset token and publish for notification
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _publishService.PublishAsync<PasswordResetInstructionSent>(new()
            {
                Email = email,
            }, Guid.NewGuid().ToString(), new
            {
                Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code))
            });
          
            return RedirectToPage("/Account/ForgotPassword/Status");
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error in password reset for {Email}", Input?.Email);
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
