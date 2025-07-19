using IdentityService.Models;

namespace IdentityService.Management.Entities;

public class ManagementPermission
{
    public ManagementPermission()
    {
        Id = IdGenerator.NewId("MGMT_PERM");
    }

    public ManagementPermission(string name, string description = "", string category = "")
    {
        Id = IdGenerator.NewId("MGMT_PERM");
        Name = name;
        Description = description;
        Category = category;
    }

    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public bool IsSystemPermission { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<ManagementRolePermission> RolePermissions { get; set; } = [];

    public void SetAsSystemPermission() => IsSystemPermission = true;
} 