using IdentityService.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityService.Data.Configurations;

public class ApplicationUserEntityConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        builder.HasIndex(u => u.Email).IsUnique();

        builder.HasIndex(u => u.UserName).IsUnique();

        builder.HasMany(u => u.UserRoles)
            .WithOne(ur => ur.User)
            .HasForeignKey(fk => fk.UserId)
            .IsRequired();

        builder.OwnsOne(u => u.Image, image =>
        {
            image.Property(i => i.HasData)
            .HasDefaultValue(true)
            .IsRequired();

            image.Property(i => i.Id).IsRequired(false);
            image.Property(i => i.Url).IsRequired(false);
        });

        builder.OwnsOne(u => u.Profile, profile =>
        {
            profile.Property(p => p.HasData)
            .HasDefaultValue(true)
            .IsRequired();

            profile.Property(p => p.Bio)
                .HasMaxLength(500)
                .IsRequired(false);

            profile.Property(p => p.WebsiteUrl)
                .HasMaxLength(255)
                .IsRequired(false);

            profile.Property(p => p.LinkedIn)
                .HasMaxLength(255)
                .IsRequired(false);

            profile.Property(p => p.Twitter)
                .HasMaxLength(255)
                .IsRequired(false);

            profile.Property(p => p.Instagram)
                .HasMaxLength(255)
                .IsRequired(false);
        });
    }
}
