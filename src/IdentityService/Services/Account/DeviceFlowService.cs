using System.Security.Claims;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using IdentityService.Models.Api.Account;
using IdentityService.Pages.Consent;
using IdentityService.Pages.Device;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class DeviceFlowService(IDeviceFlowInteractionService interaction, IEventService events) : IDeviceFlowService
{
    public async Task<DeviceContextResponse> GetContextAsync(string userCode)
    {
        if (string.IsNullOrWhiteSpace(userCode))
        {
            return new DeviceContextResponse { Success = false };
        }

        var request = await interaction.GetAuthorizationContextAsync(userCode);
        if (request == null)
        {
            return new DeviceContextResponse { Success = false, UserCode = userCode };
        }

        return CreateDeviceContext(request, userCode);
    }

    public async Task<DeviceSubmitResponse> SubmitAsync(DeviceSubmitRequest request, ClaimsPrincipal user)
    {
        var authRequest = await interaction.GetAuthorizationContextAsync(request.UserCode);
        if (authRequest == null)
        {
            return new DeviceSubmitResponse { Success = false };
        }

        ConsentResponse grantedConsent = null;
        var fieldErrors = new FieldErrorsDto();

        if (request.Button == "no")
        {
            grantedConsent = new ConsentResponse { Error = AuthorizationError.AccessDenied };
            await events.RaiseAsync(new ConsentDeniedEvent(user.GetSubjectId(), authRequest.Client.ClientId, authRequest.ValidatedResources.RawScopeValues));
            Telemetry.Metrics.ConsentDenied(authRequest.Client.ClientId, authRequest.ValidatedResources.ParsedScopes.Select(s => s.ParsedName));
        }
        else if (request.Button == "yes")
        {
            if (request.ScopesConsented.Any())
            {
                var scopes = request.ScopesConsented.ToList();
                if (ConsentOptions.EnableOfflineAccess == false)
                {
                    scopes = scopes.Where(x => x != Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess).ToList();
                }

                grantedConsent = new ConsentResponse
                {
                    RememberConsent = request.RememberConsent,
                    ScopesValuesConsented = scopes.ToArray(),
                    Description = request.Description
                };

                await events.RaiseAsync(new ConsentGrantedEvent(user.GetSubjectId(), authRequest.Client.ClientId, authRequest.ValidatedResources.RawScopeValues, grantedConsent.ScopesValuesConsented, grantedConsent.RememberConsent));
                Telemetry.Metrics.ConsentGranted(authRequest.Client.ClientId, grantedConsent.ScopesValuesConsented, grantedConsent.RememberConsent);
                var denied = authRequest.ValidatedResources.ParsedScopes.Select(s => s.ParsedName).Except(grantedConsent.ScopesValuesConsented);
                Telemetry.Metrics.ConsentDenied(authRequest.Client.ClientId, denied);
            }
            else
            {
                fieldErrors.Errors[""] = [ConsentOptions.MustChooseOneErrorMessage];
            }
        }
        else
        {
            fieldErrors.Errors[""] = [ConsentOptions.InvalidSelectionErrorMessage];
        }

        if (grantedConsent != null)
        {
            await interaction.HandleRequestAsync(request.UserCode, grantedConsent);
            return new DeviceSubmitResponse { Success = true, RedirectUrl = "/device/success" };
        }

        return new DeviceSubmitResponse { Success = false, FieldErrors = fieldErrors };
    }

    private static DeviceContextResponse CreateDeviceContext(DeviceFlowAuthorizationRequest request, string userCode)
    {
        var identityScopes = request.ValidatedResources.Resources.IdentityResources
            .Select(x => new ConsentScopeDto
            {
                Value = x.Name,
                DisplayName = x.DisplayName ?? x.Name,
                Description = x.Description,
                Emphasize = x.Emphasize,
                Required = x.Required,
                Checked = x.Required
            })
            .ToList();

        var apiScopes = new List<ConsentScopeDto>();
        foreach (var parsedScope in request.ValidatedResources.ParsedScopes)
        {
            var apiScope = request.ValidatedResources.Resources.FindApiScope(parsedScope.ParsedName);
            if (apiScope != null)
            {
                apiScopes.Add(new ConsentScopeDto
                {
                    Value = parsedScope.RawValue,
                    DisplayName = apiScope.DisplayName ?? apiScope.Name,
                    Description = apiScope.Description,
                    Emphasize = apiScope.Emphasize,
                    Required = apiScope.Required,
                    Checked = apiScope.Required
                });
            }
        }

        if (DeviceOptions.EnableOfflineAccess && request.ValidatedResources.Resources.OfflineAccess)
        {
            apiScopes.Add(new ConsentScopeDto
            {
                Value = Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = DeviceOptions.OfflineAccessDisplayName,
                Description = DeviceOptions.OfflineAccessDescription,
                Emphasize = true
            });
        }

        return new DeviceContextResponse
        {
            Success = true,
            UserCode = userCode,
            ClientName = request.Client.ClientName ?? request.Client.ClientId,
            ClientUrl = request.Client.ClientUri,
            ClientLogoUrl = request.Client.LogoUri,
            AllowRememberConsent = request.Client.AllowRememberConsent,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes
        };
    }
}
