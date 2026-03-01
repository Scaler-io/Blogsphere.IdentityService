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

    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = string.Empty;

    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
}
