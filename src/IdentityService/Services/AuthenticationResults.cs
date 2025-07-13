namespace IdentityService.Services;

// Result classes for authentication operations
public class BlogsphereAuthenticationResult
{
    public bool IsSuccess { get; set; }
    public bool RequiresTwoFactor { get; set; }
    public bool IsLockedOut { get; set; }
    public string ErrorMessage { get; set; }
    public string UserEmail { get; set; }
    public string UserType { get; set; }

    public static BlogsphereAuthenticationResult Success() => new() { IsSuccess = true };
    public static BlogsphereAuthenticationResult Failed(string errorMessage) => new() { IsSuccess = false, ErrorMessage = errorMessage };
    public static BlogsphereAuthenticationResult CreateRequiresTwoFactor(string userEmail, string userType) => new() { RequiresTwoFactor = true, UserEmail = userEmail, UserType = userType };
    public static BlogsphereAuthenticationResult LockedOut() => new() { IsLockedOut = true };
}

public class TokenValidationResult
{
    public bool IsValid { get; set; }
    public static TokenValidationResult Valid() => new() { IsValid = true };
    public static TokenValidationResult Invalid() => new() { IsValid = false };
}

public class PasswordResetResult
{
    public bool IsSuccess { get; set; }
    public string ErrorMessage { get; set; }
    public static PasswordResetResult Success() => new() { IsSuccess = true };
    public static PasswordResetResult Failed(string errorMessage) => new() { IsSuccess = false, ErrorMessage = errorMessage };
}

public class TokenGenerationResult
{
    public bool IsSuccess { get; set; }
    public string Token { get; set; }
    public string ErrorMessage { get; set; }
    public static TokenGenerationResult Success(string token) => new() { IsSuccess = true, Token = token };
    public static TokenGenerationResult Failed(string errorMessage) => new() { IsSuccess = false, ErrorMessage = errorMessage };
} 