using System.Security.Claims;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityService.Models.Api.Account;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class GrantsFlowService(
    IIdentityServerInteractionService interaction,
    IClientStore clients,
    IResourceStore resources,
    IEventService events) : IGrantsFlowService
{
    public async Task<GrantsListResponse> GetGrantsAsync(ClaimsPrincipal user)
    {
        var grants = await interaction.GetAllUserGrantsAsync();
        var list = new List<GrantDto>();

        foreach (var grant in grants)
        {
            var client = await clients.FindClientByIdAsync(grant.ClientId);
            if (client != null)
            {
                var grantResources = await resources.FindResourcesByScopeAsync(grant.Scopes);

                list.Add(new GrantDto
                {
                    ClientId = client.ClientId,
                    ClientName = client.ClientName ?? client.ClientId,
                    ClientLogoUrl = client.LogoUri,
                    ClientUrl = client.ClientUri,
                    Description = grant.Description,
                    Created = grant.CreationTime,
                    Expires = grant.Expiration,
                    IdentityGrantNames = grantResources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                    ApiGrantNames = grantResources.ApiScopes.Select(x => x.DisplayName ?? x.Name).ToArray()
                });
            }
        }

        return new GrantsListResponse { Grants = list };
    }

    public async Task<RevokeGrantResponse> RevokeGrantAsync(RevokeGrantRequest request, ClaimsPrincipal user)
    {
        await interaction.RevokeUserConsentAsync(request.ClientId);
        await events.RaiseAsync(new GrantsRevokedEvent(user.GetSubjectId(), request.ClientId));
        Telemetry.Metrics.GrantsRevoked(request.ClientId);

        return new RevokeGrantResponse { Success = true };
    }
}
