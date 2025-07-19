using IdentityService.Security;
using IdentityService.Management.Entities;

namespace IdentityService.Management.Security;

public class ManagementTwoFactorAuthTokenProvider(ILogger logger) : BaseTwoFactorTokenProvider<ManagementUser>(logger, "management")
{
} 