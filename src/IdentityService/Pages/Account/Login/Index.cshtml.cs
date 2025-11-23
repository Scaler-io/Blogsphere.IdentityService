// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Contracts.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityService.Entities;
using IdentityService.Extensions;
using IdentityService.Models;
using IdentityService.Services;
using IdentityService.Management.Entities;
using IdentityService.Management.Models;
using IdentityService.Management.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityService.Pages.Account.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index(
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
    IMultiUserStoreService multiUserStoreService) : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly UserManager<ManagementUser> _managementUserManager = managementUserManager;
    private readonly SignInManager<ManagementUser> _managementSignInManager = managementSignInManager;
    private readonly IIdentityServerInteractionService _interaction = interaction;
    private readonly IEventService _events = events;
    private readonly IAuthenticationSchemeProvider _schemeProvider = schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore = identityProviderStore;
    private readonly ILogger _logger = logger;
    private readonly IPublishService _publishService = publishService;
    private readonly IMultiUserStoreService _multiUserStoreService = multiUserStoreService;

    public ViewModel View { get; set; } = default!;

    [BindProperty]
    public InputModel Input { get; set; } = default!;

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        if(User.IsAuthenticated()){
            return Redirect("~/");
        }
        
        await BuildModelAsync(returnUrl);

        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            if (context != null)
            {
                // This "can't happen", because if the ReturnUrl was null, then the context would be null
                ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));

                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage(Input.ReturnUrl);
                }

                return Redirect(Input.ReturnUrl ?? "~/");
            }
            else
            {
                // since we don't have a valid context, then we just go back to the home page
                return Redirect("~/");
            }
        }

        // Check for required field validation
        if (string.IsNullOrWhiteSpace(Input.Username))
        {
            ModelState.AddModelError("Input.Username", "Email is required.");
        }
        
        if (string.IsNullOrWhiteSpace(Input.Password))
        {
            ModelState.AddModelError("Input.Password", "Password is required.");
        }

        if (ModelState.IsValid)
        {
            // Determine which user store to use based on the email (username)
            var userStore = await _multiUserStoreService.DetermineUserStoreByEmailAsync(Input.Username);
            
            // Validate if the user type is allowed for this client
            if (context?.Client?.ClientId != null)
            {
                var expectedUserStore = await _multiUserStoreService.DetermineUserStoreAsync(context.Client.ClientId);
                if (userStore != expectedUserStore)
                {
                    await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "user type not allowed for client", clientId: context.Client.ClientId));
                    Telemetry.Metrics.UserLoginFailure(context.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "user type not allowed for client");
                    
                    var clientRequiresManagement = expectedUserStore == ManagementConstants.ManagementUserStore;
                    var errorMessage = clientRequiresManagement 
                        ? "This application is restricted to management users only. Please use a management account to login."
                        : "This application is not available for management users. Please use a regular user account.";
                    
                    ModelState.AddModelError("Input.Username", errorMessage);
                    await BuildViewModelAsync(Input.ReturnUrl);
                    return Page();
                }
            }
            
            if (userStore == ManagementConstants.ManagementUserStore)
            {
                // Use proper ASP.NET Core Identity authentication for management users
                var managementUser = await _managementUserManager.FindByNameAsync(Input.Username);
                if(managementUser != null && !await _managementUserManager.IsEmailConfirmedAsync(managementUser))
                {
                    ModelState.AddModelError("Input.Username", "Email is not confirmed. Please confirm your email to login.");
                    await BuildViewModelAsync(Input.ReturnUrl);
                    return Page();
                }
                if(managementUser != null && !managementUser.IsActive)
                {
                    ModelState.AddModelError("Input.Username", "Your account is not active. Please contact your administrator to activate your account.");
                    await BuildViewModelAsync(Input.ReturnUrl);
                    return Page();
                }

                if (managementUser != null)
                {
                    var result = await _managementSignInManager.PasswordSignInAsync(managementUser, Input.Password, Input.RememberLogin, lockoutOnFailure: false);
                    
                    if (result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(managementUser.UserName, managementUser.Id, managementUser.FullName, clientId: context?.Client.ClientId));
                        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);
                        
                        // Management users also get 2FA
                        var code = await _managementUserManager.GenerateTwoFactorTokenAsync(managementUser, ManagementConstants.ManagementTwoFactorTokenProvider);
                        
                        await _managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACode", code);
                        await _managementUserManager.SetAuthenticationTokenAsync(managementUser, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());
                        
                        // Send code via email
                        _logger.Here().Information("Sending 2FA code to management user {code}", code);
                        await _publishService.PublishAsync(new AuthCodeSent
                        {
                            Email = managementUser.Email,
                            Code = code                   
                        }, Guid.NewGuid().ToString());
                        
                        TempData["2FA_UserEmail"] = managementUser.Email;
                        TempData["2FA_ReturnUrl"] = Input.ReturnUrl;
                        TempData["2FA_RemberMe"] = Input.RememberLogin;
                        TempData["2FA_UserType"] = "management";
                        
                        return RedirectToPage("../TwoFactor/Index");
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        return RedirectToPage("../TwoFactor/Index", new { ReturnUrl = Input.ReturnUrl, RememberMe = Input.RememberLogin });
                    }
                    else if (result.IsLockedOut)
                    {
                        return RedirectToPage("../Lockout/Index");
                    }
                    else
                    {
                        await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId: context?.Client.ClientId));
                        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
                        ModelState.AddModelError("Input.Username", LoginOptions.InvalidCredentialsErrorMessage);
                    }
                }
                else
                {
                    await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId: context?.Client.ClientId));
                    Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
                    ModelState.AddModelError("Input.Username", LoginOptions.InvalidCredentialsErrorMessage);
                }
            }
            else
            {
                // Use proper ASP.NET Core Identity authentication for blogsphere users (default)
                var blogsphereUser = await _userManager.FindByNameAsync(Input.Username);
                if (blogsphereUser != null)
                {
                    var result = await _signInManager.PasswordSignInAsync(blogsphereUser, Input.Password, Input.RememberLogin, lockoutOnFailure: false);
                    
                    if (result.Succeeded)
                    {
                        await _events.RaiseAsync(new UserLoginSuccessEvent(blogsphereUser.UserName, blogsphereUser.Id, blogsphereUser.FullName, clientId: context?.Client.ClientId));
                        Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);
                        
                        var code = await _userManager.GenerateTwoFactorTokenAsync(blogsphereUser, Constants.CustomTwoFactorTokenProvider);

                        await _userManager.SetAuthenticationTokenAsync(blogsphereUser, "2Fa", "2FACode", code);
                        await _userManager.SetAuthenticationTokenAsync(blogsphereUser, "2Fa", "2FACodeExpiry", DateTime.UtcNow.AddMinutes(5).ToString());

                        // Send code via email
                        _logger.Here().Information("Sending 2FA code to {code}", code);
                        await _publishService.PublishAsync(new AuthCodeSent
                        {
                            Email = blogsphereUser.Email,
                            Code = code                   
                        }, Guid.NewGuid().ToString());

                        TempData["2FA_UserEmail"] = blogsphereUser.Email;
                        TempData["2FA_ReturnUrl"] = Input.ReturnUrl;
                        TempData["2FA_RemberMe"] = Input.RememberLogin;
                        TempData["2FA_UserType"] = "blogsphere";

                        return RedirectToPage("../TwoFactor/Index");
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        return RedirectToPage("../TwoFactor/Index", new { ReturnUrl = Input.ReturnUrl, RememberMe = Input.RememberLogin });
                    }
                    else if (result.IsLockedOut)
                    {
                        return RedirectToPage("../Lockout/Index");
                    }
                    else
                    {
                        await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId: context?.Client.ClientId));
                        Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
                        ModelState.AddModelError("Input.Username", LoginOptions.InvalidCredentialsErrorMessage);
                    }
                }
                else
                {
                    await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, "invalid credentials", clientId: context?.Client.ClientId));
                    Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, "invalid credentials");
                    ModelState.AddModelError("Input.Username", LoginOptions.InvalidCredentialsErrorMessage);
                }
            }
        }


        // Only build model if we're not showing validation errors
        if (ModelState.IsValid)
        {
            await BuildModelAsync(Input.ReturnUrl);
        }
        else
        {
            // We have validation errors, so we need to rebuild the View model but preserve Input
            await BuildViewModelAsync(Input.ReturnUrl);
        }
        
        return Page();
    }

    private async Task BuildModelAsync(string returnUrl)
    {
        // Preserve existing Input if we have validation errors
        if (Input == null || ModelState.IsValid)
        {
            Input = new InputModel
            {
                ReturnUrl = returnUrl
            };
        }
        else
        {
            // Keep existing Input but ensure ReturnUrl is set
            if (Input != null)
            {
                Input.ReturnUrl = returnUrl;
            }
        }

        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            View = new ViewModel
            {
                EnableLocalLogin = local,
            };

            // Only overwrite username if no validation errors
            if (ModelState.IsValid && !string.IsNullOrEmpty(context.LoginHint))
            {
                Input.Username = context.LoginHint;
            }

            if (!local)
            {
                View.ExternalProviders = [new ViewModel.ExternalProvider(authenticationScheme: context.IdP)];
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Name,
                displayName: x.DisplayName ?? x.Name
            )).ToList();

        var dynamicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Scheme,
                displayName: x.DisplayName ?? x.Scheme
            ));
        providers.AddRange(dynamicSchemes);


        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Count != 0)
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }

    private async Task BuildViewModelAsync(string returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        
        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Name,
                displayName: x.DisplayName ?? x.Name
            )).ToList();

        var dynamicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Scheme,
                displayName: x.DisplayName ?? x.Scheme
            ));
        providers.AddRange(dynamicSchemes);

        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Count != 0)
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }
}
