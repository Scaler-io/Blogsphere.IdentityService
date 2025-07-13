using IdentityService.Management.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Management.Data.Configurations;

public class ManagementUserEntityConfiguration : IEntityTypeConfiguration<ManagementUser>
{
    public void Configure(EntityTypeBuilder<ManagementUser> builder)
    {
        builder.Property(u => u.FirstName)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.LastName)
            .HasMaxLength(50)
            .IsRequired();

        builder.Property(u => u.Department)
            .HasMaxLength(100);

        builder.Property(u => u.JobTitle)
            .HasMaxLength(100);

        builder.Property(u => u.EmployeeId)
            .HasMaxLength(20);

        builder.Property(u => u.CreatedBy)
            .HasMaxLength(50);

        builder.Property(u => u.UpdatedBy)
            .HasMaxLength(50);

        builder.HasIndex(u => u.EmployeeId)
            .IsUnique()
            .HasFilter("[EmployeeId] IS NOT NULL");
    }
} 