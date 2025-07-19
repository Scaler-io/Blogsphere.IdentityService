using IdentityService.Models;

namespace IdentityService.Entities;

public class ApplicationPermission(string name)
{
    public string Id { get; private init; } = IdGenerator.NewId("PERM");
    public string Name { get; set; } = name;

    public ICollection<ApplicationRolePermission> RolePermissions { get; set; } = [];
}
