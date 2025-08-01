using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Account.ForgotPassword;

public class InputModel
{
    [Required(ErrorMessage = "Please enter a valid email address")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
}
