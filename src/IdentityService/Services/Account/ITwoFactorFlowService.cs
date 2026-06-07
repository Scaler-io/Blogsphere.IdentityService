using IdentityService.Models.Api.Account;

namespace IdentityService.Services.Account;

public interface ITwoFactorFlowService
{
    Task<TwoFactorResponse> VerifyAsync(TwoFactorVerifyRequest request);

    Task<TwoFactorResponse> ResendAsync(TwoFactorResendRequest request);
}
