using System.ComponentModel.DataAnnotations;

namespace IdentityService.Pages.Account.Manage.Phone;

public class InputModel
{
    public string ReturnUrl { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;

    [Required(ErrorMessage = "Phone number is required.")]
    [RegularExpression(@"^(?:\+91|91)?[6-9]\d{9}$", ErrorMessage = "Enter a valid Indian phone number (10 digits, optional +91).")]
    [Display(Name = "Phone Number")]
    public string PhoneNumber { get; set; } = string.Empty;
}
