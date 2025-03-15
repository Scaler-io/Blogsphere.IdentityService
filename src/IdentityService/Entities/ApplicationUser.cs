using Microsoft.AspNetCore.Identity;

namespace IdentityService.Entities;

public class ApplicationUser : IdentityUser
{
    public ApplicationUser()
    {

    }

    public ApplicationUser(
        string username, string firstName, string lastname, string email)
    {
        UserName = username;
        FirstName = firstName;
        Lastname = lastname;
        Email = email;
    }

    public string FirstName { get; set; }
    public string Lastname { get; set; }
    public string Image { get; set; } = string.Empty;
    public string ImageId { get; set; } = string.Empty;
    public DateTime LastLogin { get; private set; }
    public bool IsActive { get; private set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; private set; } = "Default";

    public string UpdateBy { get; private set; } = "Default";

    public ICollection<ApplicationUserRole> UserRoles { get; set; } = [];

    // domain logics
    public void SetCreatedBy(string username) => CreatedBy = username;
    public void SetUpdatedBy(string username) => UpdateBy = username;
    public void SetUpdationTime() => UpdatedAt = DateTime.UtcNow;
    public void SetLastLogin() => LastLogin = DateTime.UtcNow;

    public void MarkEmailConfirmation() => EmailConfirmed = true;
    public void MarkPhoneConfirmation() => PhoneNumberConfirmed = true;
    public void UpdateActiveStatus(bool status = true) => IsActive = status;
}
