using IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace IdentityService.Entities;

public class ApplicationRole : IdentityRole
{
    public ApplicationRole(string name, string normalizedName)
    {
        Id = IdGenerator.NewId("ROLE");
        Name = name;
        NormalizedName = normalizedName;
    }

    public ICollection<ApplicationUserRole> UserRoles { get; set; } = [];
    public ICollection<ApplicationRolePermission> RolePermissions { get; set; } = [];
}
