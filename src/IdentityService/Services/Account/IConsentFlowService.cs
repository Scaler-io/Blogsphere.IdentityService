using IdentityService.Models.Api.Account;
using System.Security.Claims;

namespace IdentityService.Services.Account;

public interface IConsentFlowService
{
    Task<ConsentContextResponse> GetContextAsync(string returnUrl);

    Task<ConsentSubmitResponse> SubmitAsync(ConsentSubmitRequest request, ClaimsPrincipal user);
}
