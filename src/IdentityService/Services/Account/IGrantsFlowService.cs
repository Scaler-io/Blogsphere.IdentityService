using IdentityService.Models.Api.Account;
using System.Security.Claims;

namespace IdentityService.Services.Account;

public interface IGrantsFlowService
{
    Task<GrantsListResponse> GetGrantsAsync(ClaimsPrincipal user);

    Task<RevokeGrantResponse> RevokeGrantAsync(RevokeGrantRequest request, ClaimsPrincipal user);
}
