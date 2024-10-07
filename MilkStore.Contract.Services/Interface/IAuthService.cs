
using MilkStore.ModelViews.AuthModelViews;

namespace MilkStore.Contract.Repositories.Interface
{
    public interface IAuthService
    {
        Task<AuthResponse> Login(LoginModelView loginModel);
        Task<AuthResponse> RefreshToken(RefreshTokenModel refreshTokenModel);
        Task Register(RegisterModelView registerModelView);
        Task VerifyOtp(ConfirmOTPModel model, bool isResetPassword);
        Task ResendConfirmationEmail(EmailModelView emailModelView);
        Task ChangePassword(ChangePasswordModel model);
        Task ForgotPassword(EmailModelView emailModelView);
        Task ResetPassword(ResetPasswordModel resetPassword);
        Task<AuthResponse> LoginGoogle(TokenGoogleModel googleModel);
    }
}