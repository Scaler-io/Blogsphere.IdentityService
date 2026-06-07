using Contracts.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using IdentityService.Models;
using IdentityService.Models.Api.Account;
using IdentityService.Pages.Account.Login;
using IdentityService.Security;
using IdentityService.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class LoginFlowService(
    IIdentityServerInteractionService interaction,
    IAuthenticationSchemeProvider schemeProvider,
    IIdentityProviderStore identityProviderStore,
    IEventService events,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    UserManager<ManagementUser> managementUserManager,
    SignInManager<ManagementUser> managementSignInManager,
    ILogger logger,
    IPublishService publishService,
    IMultiUserStoreService multiUserStoreService,
    ITwoFactorPendingStore twoFactorPendingStore) : ILoginFlowService
{
    public async Task<LoginContextResponse> GetLoginContextAsync(string returnUrl, bool isAuthenticated)
    {
        var safeReturnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(returnUrl);

        if (isAuthenticated)
        {
            return new LoginContextResponse
            {
                IsAuthenticated = true,
                ReturnUrl = safeReturnUrl
            };
        }

        var context = await interaction.GetAuthorizationContextAsync(safeReturnUrl);

        if (context?.IdP != null && await schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;
            var providers = new List<ExternalProviderDto>();

            if (!local)
            {
                providers.Add(new ExternalProviderDto
                {
                    AuthenticationScheme = context.IdP,
                    DisplayName = context.IdP
                });
            }

            var view = new LoginContextResponse
            {
                AllowRememberLogin = LoginOptions.AllowRememberLogin,
                EnableLocalLogin = local,
                ShowSignup = !ManagementConstants.ManagementClientIds.Contains(context?.Client?.ClientId ?? ""),
                ReturnUrl = safeReturnUrl,
                Username = context.LoginHint,
                IsExternalLoginOnly = !local && providers.Count == 1,
                ExternalLoginScheme = !local && providers.Count == 1 ? context.IdP : null,
                ExternalProviders = providers,
                IsAuthenticated = false
            };

            return view;
        }

        var schemes = await schemeProvider.GetAllSchemesAsync();
        var allProviders = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProviderDto
            {
                AuthenticationScheme = x.Name,
                DisplayName = x.DisplayName ?? x.Name
            })
            .ToList();

        var dynamicSchemes = (await identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ExternalProviderDto
            {
                AuthenticationScheme = x.Scheme,
                DisplayName = x.DisplayName ?? x.Scheme
            });
        allProviders.AddRange(dynamicSchemes);

        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Count != 0)
            {
                allProviders = allProviders
                    .Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme))
                    .ToList();
            }
        }

        var enableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin;
        var isExternalOnly = enableLocalLogin == false && allProviders.Count == 1;

        return new LoginContextResponse
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = enableLocalLogin,
            ShowSignup = !ManagementConstants.ManagementClientIds.Contains(context?.Client?.ClientId ?? ""),
            ReturnUrl = safeReturnUrl,
            Username = context?.LoginHint,
            IsExternalLoginOnly = isExternalOnly,
            ExternalLoginScheme = isExternalOnly ? allProviders.SingleOrDefault()?.AuthenticationScheme : null,
            ExternalProviders = allProviders,
            IsAuthenticated = false
        };
    }

    public async Task<LoginResponse> LoginAsync(LoginRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(request.ReturnUrl);
        var context = await interaction.GetAuthorizationContextAsync(returnUrl);
        var fieldErrors = new FieldErrorsDto();

        if (string.IsNullOrWhiteSpace(request.Username))
        {
            fieldErrors.Errors["username"] = ["Email is required."];
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            fieldErrors.Errors["password"] = ["Password is required."];
        }

        if (fieldErrors.Errors.Count > 0)
        {
            return new LoginResponse
            {
                Outcome = LoginOutcome.Failed,
                FieldErrors = fieldErrors
            };
        }

        var userStore = await multiUserStoreService.DetermineUserStoreByEmailAsync(request.Username);

        if (context?.Client?.ClientId != null)
        {
            var expectedUserStore = await multiUserStoreService.DetermineUserStoreAsync(context.Client.ClientId);
            if (userStore != expectedUserStore)
            {
                await events.RaiseAsync(new UserLoginFailureEvent(request.Username, "user type not allowed for client", clientId: context.Client.ClientId));
                Telemetry.Metrics.UserLoginFailure(context.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "user type not allowed for client");

                var clientRequiresManagement = expectedUserStore == ManagementConstants.ManagementUserStore;
                var errorMessage = clientRequiresManagement
                    ? "This application is restricted to management users only. Please use a management account to login."
                    : "This application is not available for management users. Please use a regular user account.";

                fieldErrors.Errors["username"] = [errorMessage];
                return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
            }
        }

        if (userStore == ManagementConstants.ManagementUserStore)
        {
            return await LoginManagementUserAsync(request, returnUrl, context, fieldErrors);
        }

        return await LoginApplicationUserAsync(request, returnUrl, context, fieldErrors);
    }

    public async Task<LoginResponse> CancelLoginAsync(LoginCancelRequest request)
    {
        var returnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(request.ReturnUrl);
        var context = await interaction.GetAuthorizationContextAsync(returnUrl);

        if (context != null)
        {
            ArgumentNullException.ThrowIfNull(returnUrl, nameof(returnUrl));

            await interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

            return new LoginResponse
            {
                Outcome = LoginOutcome.Cancelled,
                RedirectUrl = returnUrl ?? "/",
                IsNativeClient = IdentityFlowHelpers.IsNativeClient(context)
            };
        }

        return new LoginResponse
        {
            Outcome = LoginOutcome.Cancelled,
            RedirectUrl = "/"
        };
    }

    private async Task<LoginResponse> LoginManagementUserAsync(
        LoginRequest request,
        string returnUrl,
        AuthorizationRequest context,
        FieldErrorsDto fieldErrors)
    {
        var managementUser = await managementUserManager.FindByNameAsync(request.Username);
        if (managementUser != null && !await managementUserManager.IsEmailConfirmedAsync(managementUser))
        {
            fieldErrors.Errors["username"] = ["Email is not confirmed. Please confirm your email to login."];
            return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
        }

        if (managementUser != null && !managementUser.IsActive)
        {
            fieldErrors.Errors["username"] = ["Your account is not active. Please contact your administrator to activate your account."];
            return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
        }

        if (managementUser == null)
        {
            await events.RaiseAsync(new UserLoginFailureEvent(request.Username, "invalid credentials", clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
            fieldErrors.Errors["username"] = [LoginOptions.InvalidCredentialsErrorMessage];
            return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
        }

        var result = await managementSignInManager.PasswordSignInAsync(managementUser, request.Password, request.RememberLogin, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(managementUser.UserName, managementUser.Id, managementUser.FullName, clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            managementUser.SetLastLogin();
            await managementUserManager.UpdateAsync(managementUser);

            return CreateSuccessResponse(returnUrl, context);
        }

        if (result.RequiresTwoFactor)
        {
            return await CreateTwoFactorResponseAsync(
                managementUser.Email,
                managementUser.UserName,
                managementUser.Id,
                managementUser.FullName,
                returnUrl,
                request.RememberLogin,
                "management",
                context);
        }

        if (result.IsLockedOut)
        {
            return new LoginResponse { Outcome = LoginOutcome.LockedOut };
        }

        await events.RaiseAsync(new UserLoginFailureEvent(request.Username, "invalid credentials", clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
        fieldErrors.Errors["username"] = [LoginOptions.InvalidCredentialsErrorMessage];
        return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
    }

    private async Task<LoginResponse> LoginApplicationUserAsync(
        LoginRequest request,
        string returnUrl,
        AuthorizationRequest context,
        FieldErrorsDto fieldErrors)
    {
        var blogsphereUser = await userManager.FindByNameAsync(request.Username);
        if (blogsphereUser == null)
        {
            await events.RaiseAsync(new UserLoginFailureEvent(request.Username, "invalid credentials", clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
            fieldErrors.Errors["username"] = [LoginOptions.InvalidCredentialsErrorMessage];
            return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
        }

        var result = await signInManager.PasswordSignInAsync(blogsphereUser, request.Password, request.RememberLogin, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(blogsphereUser.UserName, blogsphereUser.Id, blogsphereUser.FullName, clientId: context?.Client.ClientId));
            Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

            blogsphereUser.SetLastLogin();
            await userManager.UpdateAsync(blogsphereUser);

            return CreateSuccessResponse(returnUrl, context);
        }

        if (result.RequiresTwoFactor)
        {
            return await CreateTwoFactorResponseAsync(
                blogsphereUser.Email,
                blogsphereUser.UserName,
                blogsphereUser.Id,
                blogsphereUser.FullName,
                returnUrl,
                request.RememberLogin,
                "blogsphere",
                context);
        }

        if (result.IsLockedOut)
        {
            return new LoginResponse { Outcome = LoginOutcome.LockedOut };
        }

        await events.RaiseAsync(new UserLoginFailureEvent(request.Username, "invalid credentials", clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
        fieldErrors.Errors["username"] = [LoginOptions.InvalidCredentialsErrorMessage];
        return new LoginResponse { Outcome = LoginOutcome.Failed, FieldErrors = fieldErrors };
    }

    private async Task<LoginResponse> CreateTwoFactorResponseAsync(
        string email,
        string userName,
        string userId,
        string fullName,
        string returnUrl,
        bool rememberLogin,
        string userType,
        AuthorizationRequest context)
    {
        await events.RaiseAsync(new UserLoginSuccessEvent(userName, userId, fullName, clientId: context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

        string code;
        if (userType == "management")
        {
            var managementUser = await managementUserManager.FindByEmailAsync(email);
            code = await managementUserManager.GenerateTwoFactorTokenAsync(managementUser, ManagementConstants.ManagementTwoFactorTokenProvider);
            await managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACode", code);
            await managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());
        }
        else
        {
            var blogsphereUser = await userManager.FindByEmailAsync(email);
            code = await userManager.GenerateTwoFactorTokenAsync(blogsphereUser, Constants.CustomTwoFactorTokenProvider);
            await userManager.SetAuthenticationTokenAsync(blogsphereUser, "2Fa", "2FACode", code);
            await userManager.SetAuthenticationTokenAsync(blogsphereUser, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());
        }

        logger.Here().Information("Sending 2FA code to {UserType} user {code}", userType, code);
        await publishService.PublishAsync(new AuthCodeSent
        {
            Email = email,
            Code = code
        }, Guid.NewGuid().ToString(), new
        {
            Purpose = "TwoFactor",
            UserType = userType
        });

        var sessionId = twoFactorPendingStore.Create(new TwoFactorPendingState
        {
            Email = email,
            ReturnUrl = returnUrl,
            RememberMe = rememberLogin,
            UserType = userType
        });

        return new LoginResponse
        {
            Outcome = LoginOutcome.RequiresTwoFactor,
            TwoFactorSessionId = sessionId
        };
    }

    private static LoginResponse CreateSuccessResponse(string returnUrl, AuthorizationRequest context)
    {
        return new LoginResponse
        {
            Outcome = LoginOutcome.Success,
            RedirectUrl = returnUrl ?? "/",
            IsNativeClient = IdentityFlowHelpers.IsNativeClient(context)
        };
    }
}
