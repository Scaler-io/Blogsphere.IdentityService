using IdentityService.Entities;

namespace IdentityService.Security;

public class TwoFactorAuthTokenProvider(ILogger logger) : BaseTwoFactorTokenProvider<ApplicationUser>(logger, "blogsphere")
{
}
