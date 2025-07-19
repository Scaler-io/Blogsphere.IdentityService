using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Entities;

public class ApplicationUser : IdentityUser
{
    public ApplicationUser()
    {
        Id = IdGenerator.NewId();
    }

    public ApplicationUser(string firstName, string lastname, string email)
    {
        Id = IdGenerator.NewId();
        UserName = email; // Use email as username
        FirstName = firstName;
        Lastname = lastname;
        Email = email;
        NormalizedUserName = email.ToUpper();
        NormalizedEmail = email.ToUpper();
    }

    public string FirstName { get; set; }
    public string Lastname { get; set; }

    public ImageDetails Image { get; set; } = new();
    public ProfileDetails Profile { get; private set; } = new();

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

    public void SetProfileDetails(
        string bio = "",
        string websiteUrl = "",
        string linkedIn = "",
        string twitter = "",
        string instagram = "")
    {
        Profile = new()
        {
            Bio = bio,
            WebsiteUrl = websiteUrl,
            Instagram = instagram,
            LinkedIn = linkedIn,
            Twitter = twitter,
        };
    }

    public void SetImageDetails(string id = "", string url = "")
    {
        Image = new()
        {
            Id = id,
            Url = url,
        };
    }

    public void MarkEmailConfirmation() => EmailConfirmed = true;
    public void MarkPhoneConfirmation() => PhoneNumberConfirmed = true;
    public void UpdateActiveStatus(bool status = true) => IsActive = status;
    
    /// <summary>
    /// Gets the full name of the user
    /// </summary>
    public string FullName => $"{FirstName} {Lastname}".Trim();
}
