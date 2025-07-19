using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Management.Entities;

public class ManagementUser : IdentityUser
{
    public ManagementUser()
    {
        Id = IdGenerator.NewId();
    }

    public ManagementUser(string firstName, string lastName, string email, string department = "")
    {
        Id = IdGenerator.NewId();
        UserName = email; // Use email as username
        FirstName = firstName;
        LastName = lastName;
        Email = email;
        Department = department;
        NormalizedUserName = email.ToUpper();
        NormalizedEmail = email.ToUpper();
    }

    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public string JobTitle { get; set; } = string.Empty;
    public string EmployeeId { get; set; } = string.Empty;

    public DateTime LastLogin { get; private set; }
    public bool IsActive { get; private set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; private set; } = "System";
    public string UpdatedBy { get; private set; } = "System";

    public ICollection<ManagementUserRole> UserRoles { get; set; } = [];

    // Domain logic methods
    public void SetCreatedBy(string username) => CreatedBy = username;
    public void SetUpdatedBy(string username) => UpdatedBy = username;
    public void SetUpdationTime() => UpdatedAt = DateTime.UtcNow;
    public void SetLastLogin() => LastLogin = DateTime.UtcNow;
    public void UpdateActiveStatus(bool status = true) => IsActive = status;
    public void MarkEmailConfirmation() => EmailConfirmed = true;
    public void MarkPhoneConfirmation() => PhoneNumberConfirmed = true;

    public void SetDepartmentInfo(string department, string jobTitle, string employeeId)
    {
        Department = department;
        JobTitle = jobTitle;
        EmployeeId = employeeId;
    }

    /// <summary>
    /// Gets the full name of the management user
    /// </summary>
    public string FullName => $"{FirstName} {LastName}".Trim();
    
    /// <summary>
    /// Gets the display name with department info
    /// </summary>
    public string DisplayName => $"{FullName} ({Department})";
    
    /// <summary>
    /// Generates a management-specific employee ID
    /// </summary>
    /// <param name="department">Department code</param>
    /// <param name="role">Role abbreviation</param>
    public void GenerateEmployeeId(string department, string role)
    {
        EmployeeId = IdGenerator.NewManagementUserId(department, role);
    }
} 