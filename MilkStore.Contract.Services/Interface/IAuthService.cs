using Microsoft.AspNetCore.Identity;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.Repositories.Entity;

public interface IAuthService
{
    Task<ApplicationUser> ExistingUser(string userName);
    Task<ApplicationUser> CheckRefreshToken(string refreshToken);
    Task ChangePasswordAdmin(string id, ChangePasswordAdminModel model);
    Task<SignInResult> CheckPassword(LoginModelView loginModel);
    (string token, IEnumerable<string> roles) GenerateJwtToken(ApplicationUser user);
    Task<string> GenerateRefreshToken(ApplicationUser user);
    Task<string> ForgotPassword(string email);
    Task ResetPassword(string email, string password, string token);
}