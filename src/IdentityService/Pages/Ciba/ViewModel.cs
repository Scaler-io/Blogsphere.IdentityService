// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

namespace IdentityService.Pages.Ciba;

public class ViewModel
{
    public string ClientName { get; set; }
    public string ClientUrl { get; set; }
    public string ClientLogoUrl { get; set; }

    public string BindingMessage { get; set; }

    public IEnumerable<ScopeViewModel> IdentityScopes { get; set; } = Enumerable.Empty<ScopeViewModel>();
    public IEnumerable<ScopeViewModel> ApiScopes { get; set; } = Enumerable.Empty<ScopeViewModel>();
}

public class ScopeViewModel
{
    public string Name { get; set; }
    public string Value { get; set; }
    public string DisplayName { get; set; }
    public string Description { get; set; }
    public bool Emphasize { get; set; }
    public bool Required { get; set; }
    public bool Checked { get; set; }
    public IEnumerable<ResourceViewModel> Resources { get; set; } = Enumerable.Empty<ResourceViewModel>();
}

public class ResourceViewModel
{
    public string Name { get; set; }
    public string DisplayName { get; set; }
}