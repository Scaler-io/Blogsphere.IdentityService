using IdentityService.Management.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Management.Data.Configurations;

public class ManagementPermissionEntityConfiguration : IEntityTypeConfiguration<ManagementPermission>
{
    public void Configure(EntityTypeBuilder<ManagementPermission> builder)
    {
        builder.HasKey(p => p.Id);

        builder.Property(p => p.Name)
            .HasMaxLength(100)
            .IsRequired();

        builder.Property(p => p.Description)
            .HasMaxLength(500);

        builder.Property(p => p.Category)
            .HasMaxLength(50);

        builder.HasIndex(p => p.Name)
            .IsUnique();

        builder.HasIndex(p => p.Category);
    }
} 