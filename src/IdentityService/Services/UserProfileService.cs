using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdentityService.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;

namespace IdentityService.Services;

public class UserProfileService(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager) : IProfileService
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly RoleManager<ApplicationRole> _roleManager = roleManager;

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        var roles = await _userManager.GetRolesAsync(user);
        var permissions = new List<ApplicationPermission>();

        foreach (var roleName in roles)
        {
           var rolePermissions = await _roleManager.Roles
                .Where(r => r.Name == roleName)
                .SelectMany(r => r.RolePermissions.Select(rp => rp.Permission.Name).ToList())
                .ToListAsync();

            var existingClaims = await _userManager.GetClaimsAsync(user);

            var claims = new List<Claim>
            {
                new Claim("roles", JsonConvert.SerializeObject(roles)),
                new Claim("permissions", JsonConvert.SerializeObject(rolePermissions))
            };
            if (existingClaims is not null)
            {
                context.IssuedClaims.Add(existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName));
                context.IssuedClaims.Add(existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName));
                context.IssuedClaims.Add(existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name));
                context.IssuedClaims.Add(existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email));
            }
            context.IssuedClaims.AddRange(claims);
        }
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
        return Task.CompletedTask;
    }
}
