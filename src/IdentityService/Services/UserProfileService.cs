using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;

namespace IdentityService.Services;

public class UserProfileService(
    UserManager<ApplicationUser> applicationUserManager,
    UserManager<ManagementUser> managementUserManager,
    RoleManager<ApplicationRole> applicationRoleManager,
    RoleManager<ManagementRole> managementRoleManager,
    IMultiUserStoreService multiUserStoreService,
    ILogger logger) : IProfileService
{
    private readonly UserManager<ApplicationUser> _applicationUserManager = applicationUserManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly RoleManager<ApplicationRole> _applicationRoleManager = applicationRoleManager;
    private readonly RoleManager<ManagementRole> _managementRoleManager = managementRoleManager;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;
    private readonly ILogger _logger = logger;

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        try
        {
            // Get the user's email from the subject
            var email = context.Subject.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
            {
                _logger.Here().Warning("No email found in subject claims");
                return;
            }

            // Determine which user store to use based on email
            var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(email);
            _logger.Here().Information("Determined user store {UserStore} for email {Email}", userStore, email);

            if (userStore == ManagementConstants.ManagementUserStore)
            {
                await GetManagementUserProfileDataAsync(context, email);
            }
            else
            {
                await GetApplicationUserProfileDataAsync(context, email);
            }
        }
        catch (Exception ex)
        {
            _logger.Here().Error(ex, "Error getting profile data");
        }
    }

    private async Task GetApplicationUserProfileDataAsync(ProfileDataRequestContext context, string email)
    {
        var user = await _applicationUserManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.Here().Warning("ApplicationUser not found for email {Email}", email);
            return;
        }

        var roles = await _applicationUserManager.GetRolesAsync(user);
        var permissions = new List<string>();

        foreach (var roleName in roles)
        {
            var rolePermissions = await _applicationRoleManager.Roles
                .Where(r => r.Name == roleName)
                .SelectMany(r => r.RolePermissions.Select(rp => rp.Permission.Name))
                .ToListAsync();
            permissions.AddRange(rolePermissions);
        }

        var existingClaims = await _applicationUserManager.GetClaimsAsync(user);

        var claims = new List<Claim>
        {
            new("user_type", "application"),
            new("roles", JsonConvert.SerializeObject(roles)),
            new("permissions", JsonConvert.SerializeObject(permissions))
        };

        // Add existing claims
        if (existingClaims != null)
        {
            var givenNameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName);
            if (givenNameClaim != null)
                context.IssuedClaims.Add(givenNameClaim);
                
            var familyNameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName);
            if (familyNameClaim != null)
                context.IssuedClaims.Add(familyNameClaim);
                
            var nameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name);
            if (nameClaim != null)
                context.IssuedClaims.Add(nameClaim);
                
            var emailClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email);
            if (emailClaim != null)
                context.IssuedClaims.Add(emailClaim);
        }

        context.IssuedClaims.AddRange(claims);
    }

    private async Task GetManagementUserProfileDataAsync(ProfileDataRequestContext context, string email)
    {
        var user = await _managementUserManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.Here().Warning("ManagementUser not found for email {Email}", email);
            return;
        }

        var roles = await _managementUserManager.GetRolesAsync(user);
        var permissions = new List<string>();

        foreach (var roleName in roles)
        {
            var rolePermissions = await _managementRoleManager.Roles
                .Where(r => r.Name == roleName)
                .SelectMany(r => r.RolePermissions.Select(rp => rp.Permission.Name))
                .ToListAsync();
            permissions.AddRange(rolePermissions);
        }

        var existingClaims = await _managementUserManager.GetClaimsAsync(user);

        var claims = new List<Claim>
        {
            new("user_type", "management"),
            new("roles", JsonConvert.SerializeObject(roles)),
            new("permissions", JsonConvert.SerializeObject(permissions))
        };

        // Add existing claims
        if (existingClaims != null)
        {
            var givenNameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName);
            if (givenNameClaim != null)
                context.IssuedClaims.Add(givenNameClaim);
                
            var familyNameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName);
            if (familyNameClaim != null)
                context.IssuedClaims.Add(familyNameClaim);
                
            var nameClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name);
            if (nameClaim != null)
                context.IssuedClaims.Add(nameClaim);
                
            var emailClaim = existingClaims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email);
            if (emailClaim != null)
                context.IssuedClaims.Add(emailClaim);
        }

        context.IssuedClaims.AddRange(claims);
    }

    public Task IsActiveAsync(IsActiveContext context)
    {
        return Task.CompletedTask;
    }
}
