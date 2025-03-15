using IdentityService.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Data.Configurations;

public class ApplicationPermissionEntityConfiguration : IEntityTypeConfiguration<ApplicationPermission>
{
    public void Configure(EntityTypeBuilder<ApplicationPermission> builder)
    {
        builder.HasIndex(p => p.Name).IsUnique();

        builder.HasMany(rp => rp.RolePermissions)
            .WithOne(p => p.Permission)
            .HasForeignKey(fk => fk.PermissionId)
            .IsRequired();
    }
}
