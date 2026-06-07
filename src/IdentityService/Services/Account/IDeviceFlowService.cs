using IdentityService.Models.Api.Account;
using System.Security.Claims;

namespace IdentityService.Services.Account;

public interface IDeviceFlowService
{
    Task<DeviceContextResponse> GetContextAsync(string userCode);

    Task<DeviceSubmitResponse> SubmitAsync(DeviceSubmitRequest request, ClaimsPrincipal user);
}
