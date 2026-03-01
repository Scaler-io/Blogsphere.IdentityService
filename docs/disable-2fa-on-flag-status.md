# Disable 2FA Based on TwoFactorEnabled Flag

## Overview

This change makes Two-Factor Authentication (2FA) conditional during login. When a user's `TwoFactorEnabled` flag is `false`, the login flow completes immediately after password verification -- the 2FA page is never shown and no verification code is generated or emailed. When the flag is `true`, the existing 2FA flow is preserved without modification.

## Rationale

Previously, all users were unconditionally redirected to the 2FA verification page after a successful password sign-in. The `TwoFactorEnabled` property (inherited from ASP.NET Core Identity's `IdentityUser`) already existed in the database for both `ApplicationUser` and `ManagementUser` tables, but was never consulted.

This change respects the flag so that:

- Users/applications that do not require 2FA can log in without the extra step.
- Users/applications that require 2FA continue to use the full verification flow.
- No database migration is needed -- the column already exists.

## Affected Files

| File | Change |
|------|--------|
| `src/IdentityService/Pages/Account/Login/Index.cshtml.cs` | Added `TwoFactorEnabled` check after successful password sign-in for both Management and Blogsphere users. When disabled, performs direct sign-in and redirects without triggering 2FA. |
| `src/IdentityService/Services/BaseAuthenticationService.cs` | Added `TwoFactorEnabled` check in `AuthenticateAsync`. When disabled, signs in directly and returns `Success()` instead of `RequiresTwoFactor`. |
| `src/IdentityService/Security/BaseTwoFactorTokenProvider.cs` | Updated `CanGenerateTwoFactorTokenAsync` to check `user.TwoFactorEnabled` via `UserManager.GetTwoFactorEnabledAsync()` instead of always returning `true`. This acts as a defense-in-depth guard. |

## Unaffected Components

| Component | Reason |
|-----------|--------|
| `Pages/Account/TwoFactor/Index.cshtml.cs` | No changes needed -- page still works correctly when reached by users with 2FA enabled. |
| `MultiUserResourceOwnerPasswordValidator` | Only validates passwords for Resource Owner Password grant; has no 2FA logic. |
| `ForgotPassword / ResetPassword` | Uses password reset tokens, completely separate from 2FA tokens. |
| `UserProfileService` | Handles profile claims only; no authentication logic. |
| `DelegationGrantValidator` | Token exchange grant; no 2FA involvement. |
| `Config.cs` (Clients/Scopes/Resources) | No changes to Duende IdentityServer configuration. |
| Database / Migrations | `TwoFactorEnabled` column already exists in both `AspNetUsers` tables. |

## Login Flow (After Change)

```
User submits credentials
        |
        v
  Password valid?
   /          \
  No           Yes
  |             |
Show error   TwoFactorEnabled?
              /          \
            Yes           No
             |             |
     Generate code    Sign in directly
     Send via email   Update last login
     Redirect to      Redirect to returnUrl
     TwoFactor page
             |
        Code valid?
         /      \
       No       Yes
       |         |
    Show error  Sign in
                Update last login
                Redirect to returnUrl
```

## Backward Compatibility Note

`TwoFactorEnabled` defaults to `false` in `IdentityUser`. After this change, existing users whose `TwoFactorEnabled` was never explicitly set to `true` will skip 2FA. If existing users should continue using 2FA, run a data update:

```sql
-- For Blogsphere users
UPDATE [dbo].[AspNetUsers] SET TwoFactorEnabled = 1;

-- For Management users (if using separate schema)
UPDATE [Management].[AspNetUsers] SET TwoFactorEnabled = 1;
```

## Testing Checklist

### Blogsphere User Tests

- [ ] User with `TwoFactorEnabled = false` can log in without seeing the 2FA page.
- [ ] User with `TwoFactorEnabled = true` is redirected to the 2FA page and must enter a valid code.
- [ ] User with `TwoFactorEnabled = true` receives the verification email.
- [ ] Invalid password still shows error regardless of `TwoFactorEnabled` value.
- [ ] Remember me option works correctly in both 2FA and non-2FA paths.
- [ ] `LastLogin` is updated in both paths.
- [ ] Redirect to `returnUrl` works correctly in both paths.

### Management User Tests

- [ ] Management user with `TwoFactorEnabled = false` can log in without seeing the 2FA page.
- [ ] Management user with `TwoFactorEnabled = true` is redirected to the 2FA page and must enter a valid code.
- [ ] Management user with `TwoFactorEnabled = true` receives the verification email.
- [ ] Invalid password still shows error regardless of `TwoFactorEnabled` value.
- [ ] Email confirmation and active status checks still work before 2FA check.
- [ ] `LastLogin` is updated in both paths.

### Service Layer Tests

- [ ] `BaseAuthenticationService.AuthenticateAsync` returns `Success()` when `TwoFactorEnabled = false`.
- [ ] `BaseAuthenticationService.AuthenticateAsync` returns `RequiresTwoFactor` when `TwoFactorEnabled = true`.
- [ ] `ValidateTwoFactorTokenAsync` still works correctly for users who went through 2FA.

### Token Provider Tests

- [ ] `CanGenerateTwoFactorTokenAsync` returns `false` when `TwoFactorEnabled = false`.
- [ ] `CanGenerateTwoFactorTokenAsync` returns `true` when `TwoFactorEnabled = true`.

### Regression Tests

- [ ] Resource Owner Password flow (Postman clients) still works -- no 2FA involved.
- [ ] Forgot Password flow still works.
- [ ] Reset Password flow still works.
- [ ] Email verification flow still works.
- [ ] Logout flow still works.
- [ ] User type validation (Management vs Blogsphere client restrictions) still works.
