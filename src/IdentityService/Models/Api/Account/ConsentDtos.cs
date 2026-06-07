namespace IdentityService.Models.Api.Account;

public class ConsentContextRequest
{
    public string ReturnUrl { get; set; }
}

public class ConsentScopeDto
{
    public string Name { get; set; }

    public string Value { get; set; }

    public string DisplayName { get; set; }

    public string Description { get; set; }

    public bool Emphasize { get; set; }

    public bool Required { get; set; }

    public bool Checked { get; set; }
}

public class ConsentContextResponse
{
    public string ClientName { get; set; }

    public string ClientUrl { get; set; }

    public string ClientLogoUrl { get; set; }

    public bool AllowRememberConsent { get; set; }

    public string ReturnUrl { get; set; }

    public IEnumerable<ConsentScopeDto> IdentityScopes { get; set; } = [];

    public IEnumerable<ConsentScopeDto> ApiScopes { get; set; } = [];
}

public class ConsentSubmitRequest
{
    public string ReturnUrl { get; set; }

    public string Button { get; set; }

    public bool RememberConsent { get; set; }

    public IEnumerable<string> ScopesConsented { get; set; } = [];

    public string Description { get; set; }
}

public class ConsentSubmitResponse
{
    public bool Success { get; set; }

    public string RedirectUrl { get; set; }

    public bool IsNativeClient { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}

public class DeviceContextRequest
{
    public string UserCode { get; set; }
}

public class DeviceContextResponse
{
    public bool Success { get; set; }

    public string UserCode { get; set; }

    public string ClientName { get; set; }

    public string ClientUrl { get; set; }

    public string ClientLogoUrl { get; set; }

    public bool AllowRememberConsent { get; set; }

    public IEnumerable<ConsentScopeDto> IdentityScopes { get; set; } = [];

    public IEnumerable<ConsentScopeDto> ApiScopes { get; set; } = [];
}

public class DeviceSubmitRequest
{
    public string UserCode { get; set; }

    public string Button { get; set; }

    public bool RememberConsent { get; set; }

    public IEnumerable<string> ScopesConsented { get; set; } = [];

    public string Description { get; set; }
}

public class DeviceSubmitResponse
{
    public bool Success { get; set; }

    public string RedirectUrl { get; set; }

    public FieldErrorsDto FieldErrors { get; set; }
}

public class GrantDto
{
    public string ClientId { get; set; }

    public string ClientName { get; set; }

    public string ClientUrl { get; set; }

    public string ClientLogoUrl { get; set; }

    public string Description { get; set; }

    public DateTime Created { get; set; }

    public DateTime? Expires { get; set; }

    public IEnumerable<string> IdentityGrantNames { get; set; } = [];

    public IEnumerable<string> ApiGrantNames { get; set; } = [];
}

public class GrantsListResponse
{
    public IEnumerable<GrantDto> Grants { get; set; } = [];
}

public class RevokeGrantRequest
{
    public string ClientId { get; set; }
}

public class RevokeGrantResponse
{
    public bool Success { get; set; }
}

public class ManageStubResponse
{
    public bool Implemented { get; set; }

    public string Message { get; set; }
}
