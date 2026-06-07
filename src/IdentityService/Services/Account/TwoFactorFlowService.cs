using Contracts.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Models;
using IdentityService.Models.Api.Account;
using IdentityService.Security;
using IdentityService.Services;
using Microsoft.AspNetCore.Identity;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class TwoFactorFlowService(
    ILogger logger,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ManagementUser> managementUserManager,
    SignInManager<ManagementUser> managementSignInManager,
    IEventService events,
    IIdentityServerInteractionService interaction,
    IPublishService publishService,
    ITwoFactorPendingStore twoFactorPendingStore) : ITwoFactorFlowService
{
    public async Task<TwoFactorResponse> ResendAsync(TwoFactorResendRequest request)
    {
        var pending = twoFactorPendingStore.Get(request.TwoFactorSessionId);
        if (pending == null)
        {
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.SessionExpired };
        }

        var returnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(pending.ReturnUrl);

        if (pending.UserType == "management")
        {
            var managementUser = await managementUserManager.FindByEmailAsync(pending.Email);
            if (managementUser == null)
            {
                twoFactorPendingStore.Remove(request.TwoFactorSessionId);
                return new TwoFactorResponse { Outcome = TwoFactorOutcome.SessionExpired };
            }

            var code = await managementUserManager.GenerateTwoFactorTokenAsync(managementUser, ManagementConstants.ManagementTwoFactorTokenProvider);
            await managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACode", code);
            await managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());

            logger.Here().Information("Resending 2FA code to management user {Email}", pending.Email);
            await publishService.PublishAsync(new AuthCodeSent
            {
                Email = managementUser.Email,
                Code = code
            }, Guid.NewGuid().ToString(), new
            {
                Purpose = "TwoFactor",
                UserType = "management"
            });
        }
        else
        {
            var user = await userManager.FindByEmailAsync(pending.Email);
            if (user == null)
            {
                twoFactorPendingStore.Remove(request.TwoFactorSessionId);
                return new TwoFactorResponse { Outcome = TwoFactorOutcome.SessionExpired };
            }

            var code = await userManager.GenerateTwoFactorTokenAsync(user, Constants.CustomTwoFactorTokenProvider);
            await userManager.SetAuthenticationTokenAsync(user, "2Fa", "2FACode", code);
            await userManager.SetAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());

            logger.Here().Information("Resending 2FA code to blogsphere user {Email}", pending.Email);
            await publishService.PublishAsync(new AuthCodeSent
            {
                Email = user.Email,
                Code = code
            }, Guid.NewGuid().ToString(), new
            {
                Purpose = "TwoFactor",
                UserType = "blogsphere"
            });
        }

        twoFactorPendingStore.Refresh(request.TwoFactorSessionId);

        return new TwoFactorResponse
        {
            Outcome = TwoFactorOutcome.Success,
            StatusMessage = "A new verification code has been sent to your email."
        };
    }

    public async Task<TwoFactorResponse> VerifyAsync(TwoFactorVerifyRequest request)
    {
        var pending = twoFactorPendingStore.Get(request.TwoFactorSessionId);
        if (pending == null)
        {
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.SessionExpired };
        }

        var returnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(pending.ReturnUrl);
        var context = await interaction.GetAuthorizationContextAsync(returnUrl);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrEmpty(request.Code))
        {
            fieldErrors.Errors["code"] = ["Code is required"];
            twoFactorPendingStore.Refresh(request.TwoFactorSessionId);
            return new TwoFactorResponse
            {
                Outcome = TwoFactorOutcome.Failed,
                FieldErrors = fieldErrors
            };
        }

        if (pending.UserType == "management")
        {
            return await VerifyManagementUserAsync(pending, request, returnUrl, context, fieldErrors);
        }

        return await VerifyApplicationUserAsync(pending, request, returnUrl, context, fieldErrors);
    }

    private async Task<TwoFactorResponse> VerifyManagementUserAsync(
        TwoFactorPendingState pending,
        TwoFactorVerifyRequest request,
        string returnUrl,
        Duende.IdentityServer.Models.AuthorizationRequest context,
        FieldErrorsDto fieldErrors)
    {
        var managementUser = await managementUserManager.FindByEmailAsync(pending.Email);
        if (managementUser == null)
        {
            fieldErrors.Errors[""] = ["Invalid user."];
            twoFactorPendingStore.Refresh(request.TwoFactorSessionId);
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.Failed, FieldErrors = fieldErrors };
        }

        var result = await managementUserManager.VerifyTwoFactorTokenAsync(managementUser, ManagementConstants.ManagementTwoFactorTokenProvider, request.Code);
        if (!result)
        {
            fieldErrors.Errors["code"] = ["The code is invalid"];
            twoFactorPendingStore.Refresh(request.TwoFactorSessionId);
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.Failed, FieldErrors = fieldErrors };
        }

        await managementSignInManager.SignInAsync(managementUser, pending.RememberMe);
        await managementUserManager.RemoveAuthenticationTokenAsync(managementUser, "2Fa", "2FACode");
        await managementUserManager.RemoveAuthenticationTokenAsync(managementUser, "2Fa", "2FACodeExpiry");

        await events.RaiseAsync(new UserLoginSuccessEvent(managementUser.UserName, managementUser.Id, managementUser.FullName, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

        managementUser.SetLastLogin();
        await managementUserManager.UpdateAsync(managementUser);

        twoFactorPendingStore.Remove(request.TwoFactorSessionId);

        return new TwoFactorResponse
        {
            Outcome = TwoFactorOutcome.Success,
            RedirectUrl = returnUrl,
            IsNativeClient = IdentityFlowHelpers.IsNativeClient(context)
        };
    }

    private async Task<TwoFactorResponse> VerifyApplicationUserAsync(
        TwoFactorPendingState pending,
        TwoFactorVerifyRequest request,
        string returnUrl,
        Duende.IdentityServer.Models.AuthorizationRequest context,
        FieldErrorsDto fieldErrors)
    {
        var user = await userManager.FindByEmailAsync(pending.Email);
        if (user == null)
        {
            fieldErrors.Errors[""] = ["Invalid user."];
            twoFactorPendingStore.Refresh(request.TwoFactorSessionId);
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.Failed, FieldErrors = fieldErrors };
        }

        var result = await userManager.VerifyTwoFactorTokenAsync(user, Constants.CustomTwoFactorTokenProvider, request.Code);
        if (!result)
        {
            fieldErrors.Errors["code"] = ["The code is invalid"];
            twoFactorPendingStore.Refresh(request.TwoFactorSessionId);
            return new TwoFactorResponse { Outcome = TwoFactorOutcome.Failed, FieldErrors = fieldErrors };
        }

        await signInManager.SignInAsync(user, pending.RememberMe);
        await userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACode");
        await userManager.RemoveAuthenticationTokenAsync(user, "2Fa", "2FACodeExpiry");

        await events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.FullName, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

        user.SetLastLogin();
        await userManager.UpdateAsync(user);

        twoFactorPendingStore.Remove(request.TwoFactorSessionId);

        return new TwoFactorResponse
        {
            Outcome = TwoFactorOutcome.Success,
            RedirectUrl = returnUrl,
            IsNativeClient = IdentityFlowHelpers.IsNativeClient(context)
        };
    }
}
