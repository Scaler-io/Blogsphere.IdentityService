using System.Security.Claims;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityService.Models.Api.Account;
using IdentityService.Pages.Consent;
using IdentityService.Security;
using Telemetry = IdentityService.Pages.Telemetry;

namespace IdentityService.Services.Account;

public class ConsentFlowService(IIdentityServerInteractionService interaction, IEventService events) : IConsentFlowService
{
    public async Task<ConsentContextResponse> GetContextAsync(string returnUrl)
    {
        var safeReturnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(returnUrl);
        var request = await interaction.GetAuthorizationContextAsync(safeReturnUrl);

        if (request == null)
        {
            return null;
        }

        return CreateConsentContext(request, safeReturnUrl);
    }

    public async Task<ConsentSubmitResponse> SubmitAsync(ConsentSubmitRequest request, ClaimsPrincipal user)
    {
        request.ReturnUrl = ReturnUrlGuard.NormalizeForIdentityFlow(request.ReturnUrl);
        var authRequest = await interaction.GetAuthorizationContextAsync(request.ReturnUrl);

        if (authRequest == null)
        {
            return new ConsentSubmitResponse { Success = false };
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
            await interaction.GrantConsentAsync(authRequest, grantedConsent);

            return new ConsentSubmitResponse
            {
                Success = true,
                RedirectUrl = request.ReturnUrl,
                IsNativeClient = IdentityFlowHelpers.IsNativeClient(authRequest)
            };
        }

        return new ConsentSubmitResponse { Success = false, FieldErrors = fieldErrors };
    }

    private static ConsentContextResponse CreateConsentContext(AuthorizationRequest request, string returnUrl)
    {
        var identityScopes = request.ValidatedResources.Resources.IdentityResources
            .Select(x => new ConsentScopeDto
            {
                Name = x.Name,
                Value = x.Name,
                DisplayName = x.DisplayName ?? x.Name,
                Description = x.Description,
                Emphasize = x.Emphasize,
                Required = x.Required,
                Checked = x.Required
            })
            .ToList();

        var resourceIndicators = request.Parameters.GetValues(OidcConstants.AuthorizeRequest.Resource) ?? Enumerable.Empty<string>();
        var apiResources = request.ValidatedResources.Resources.ApiResources.Where(x => resourceIndicators.Contains(x.Name));

        var apiScopes = new List<ConsentScopeDto>();
        foreach (var parsedScope in request.ValidatedResources.ParsedScopes)
        {
            var apiScope = request.ValidatedResources.Resources.FindApiScope(parsedScope.ParsedName);
            if (apiScope != null)
            {
                apiScopes.Add(new ConsentScopeDto
                {
                    Name = parsedScope.ParsedName,
                    Value = parsedScope.RawValue,
                    DisplayName = apiScope.DisplayName ?? apiScope.Name,
                    Description = apiScope.Description,
                    Emphasize = apiScope.Emphasize,
                    Required = apiScope.Required,
                    Checked = apiScope.Required
                });
            }
        }

        if (ConsentOptions.EnableOfflineAccess && request.ValidatedResources.Resources.OfflineAccess)
        {
            apiScopes.Add(new ConsentScopeDto
            {
                Value = Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = ConsentOptions.OfflineAccessDisplayName,
                Description = ConsentOptions.OfflineAccessDescription,
                Emphasize = true
            });
        }

        return new ConsentContextResponse
        {
            ClientName = request.Client.ClientName ?? request.Client.ClientId,
            ClientUrl = request.Client.ClientUri,
            ClientLogoUrl = request.Client.LogoUri,
            AllowRememberConsent = request.Client.AllowRememberConsent,
            ReturnUrl = returnUrl,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes
        };
    }
}
