using IdentityService.Management.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Management.Data.Configurations;

public class ManagementRoleEntityConfiguration : IEntityTypeConfiguration<ManagementRole>
{
    public void Configure(EntityTypeBuilder<ManagementRole> builder)
    {
        builder.Property(r => r.Description)
            .HasMaxLength(500);

        builder.Property(r => r.Name)
            .HasMaxLength(256)
            .IsRequired();

        builder.Property(r => r.NormalizedName)
            .HasMaxLength(256);
    }
} 