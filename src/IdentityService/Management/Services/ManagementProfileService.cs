using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Extensions;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityService.Management.Services;

public class ManagementProfileService(
    UserManager<ManagementUser> userManager,
    ILogger logger) : IProfileService
{
    private readonly UserManager<ManagementUser> _userManager = userManager;
    private readonly ILogger _logger = logger;

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        if (user == null)
        {
            _logger.Here().Warning("User not found for subject: {Subject}", context.Subject.GetSubjectId());
            return;
        }

        var claims = new List<Claim>
        {
            new("sub", user.Id),
            new("name", user.FullName),
            new("given_name", user.FirstName),
            new("family_name", user.LastName),
            new("email", user.Email ?? string.Empty),
            new("employee_id", user.EmployeeId ?? string.Empty),
            new("department", user.Department ?? string.Empty),
            new("job_title", user.JobTitle ?? string.Empty),
            new("user_type", "management")
        };

        // Add roles
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim("role", role));
        }

        // Add user claims
        var userClaims = await _userManager.GetClaimsAsync(user);
        claims.AddRange(userClaims);

        context.IssuedClaims = claims.Where(x => context.RequestedClaimTypes.Contains(x.Type)).ToList();
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        var user = await _userManager.GetUserAsync(context.Subject);
        context.IsActive = user?.IsActive == true;
    }
} 