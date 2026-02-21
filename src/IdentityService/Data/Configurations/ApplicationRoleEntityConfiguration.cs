using IdentityService.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Data.Configurations;

public class ApplicationRoleEntityConfiguration : IEntityTypeConfiguration<ApplicationRole>
{
    public void Configure(EntityTypeBuilder<ApplicationRole> builder)
    {
        builder.HasMany(rp => rp.RolePermissions)
            .WithOne(r => r.Role)
            .HasForeignKey(fk => fk.RoleId)
            .IsRequired();
    }
}
