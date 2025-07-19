using IdentityService.Data.Configurations;
using IdentityService.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityService.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(ApplicationPermissionEntityConfiguration).Assembly);
        builder.Entity<ApplicationRolePermission>()
            .HasKey(ck => new { ck.RoleId, ck.PermissionId });

        builder.Owned<ProfileDetails>();
        builder.Owned<ImageDetails>();
    }

    // permission sets
    public DbSet<ApplicationPermission> Permissions { get; set; }
    public DbSet<ApplicationRolePermission> RolePermissions { get; set; }
}
