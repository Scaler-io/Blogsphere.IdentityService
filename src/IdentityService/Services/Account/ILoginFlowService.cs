using IdentityService.Models.Api.Account;

namespace IdentityService.Services.Account;

public interface ILoginFlowService
{
    Task<LoginContextResponse> GetLoginContextAsync(string returnUrl, bool isAuthenticated);

    Task<LoginResponse> LoginAsync(LoginRequest request);

    Task<LoginResponse> CancelLoginAsync(LoginCancelRequest request);
}
