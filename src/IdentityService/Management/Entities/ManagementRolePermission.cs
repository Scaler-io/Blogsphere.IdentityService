using Microsoft.EntityFrameworkCore;

namespace IdentityService.Management.Entities;

[PrimaryKey(nameof(RoleId), nameof(PermissionId))]
public class ManagementRolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public string PermissionId { get; set; } = string.Empty;
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    public string AssignedBy { get; set; } = "System";

    public ManagementRole Role { get; set; } = null!;
    public ManagementPermission Permission { get; set; } = null!;

    public void SetAssignedBy(string username) => AssignedBy = username;
} 