using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Management.Entities;

public class ManagementRole : IdentityRole
{
    public ManagementRole()
    {
        Id = IdGenerator.NewId("MGMT_ROLE");
    }

    public ManagementRole(string name, string normalizedName, string description = "")
    {
        Id = IdGenerator.NewId("MGMT_ROLE");
        Name = name;
        NormalizedName = normalizedName;
        Description = description;
    }

    public string Description { get; set; } = string.Empty;
    public bool IsSystemRole { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<ManagementUserRole> UserRoles { get; set; } = [];
    public ICollection<ManagementRolePermission> RolePermissions { get; set; } = [];

    public void SetAsSystemRole() => IsSystemRole = true;
    public void SetUpdationTime() => UpdatedAt = DateTime.UtcNow;
} 