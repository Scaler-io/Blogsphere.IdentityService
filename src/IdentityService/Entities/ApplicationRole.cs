using Microsoft.AspNetCore.Identity;

namespace IdentityService.Entities;

public class ApplicationRole : IdentityRole
{
    public ApplicationRole(string name, string normalizedName)
    {
        Name = name;
        NormalizedName = normalizedName;
    }

    public ICollection<ApplicationUserRole> UserRoles { get; set; } = [];
    public ICollection<ApplicationRolePermission> RolePermissions { get; set; } = [];
}
