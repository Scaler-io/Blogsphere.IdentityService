using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Account.SelfResetPassword.ChangePassword;

public class InputModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    public string ReturnUrl { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    public string Mode { get; set; } = "current";

    [DataType(DataType.Password)]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "New password is required.")]
    [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    [Display(Name = "New password")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm password is required.")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm password")]
    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
