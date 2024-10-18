using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.AuthModelViews;


namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        private readonly IAuthService _authService = authService;

        [HttpPost("Auth_Account")]
        public async Task<IActionResult> Login(LoginModelView model)
        {
            AuthResponse? result = await _authService.Login(model);
            return Ok(BaseResponse<AuthResponse>.OkResponse(result));
        }

        [HttpPost("New_Account")]
        public async Task<IActionResult> Register(RegisterModelView model)
        {
            await _authService.Register(model);
            return Ok(BaseResponse<string>.OkResponse("Đăng ký thành công, vui lòng kiểm tra email để xác nhận"));
        }

        [HttpPatch("Confirm_Email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmOTPModel confirmOTPModel)
        {
            await _authService.VerifyOtp(confirmOTPModel, false);
            return Ok(BaseResponse<string>.OkResponse("Xác nhận email thành công!"));
        }

        [HttpPatch("Resend_Confirmation_Email")]
        public async Task<IActionResult> ResendConfirmationEmail(EmailModelView model)
        {
            await _authService.ResendConfirmationEmail(model);
            return Ok(BaseResponse<string>.OkResponse("Emaill đã được gửi lại!"));
        }

        [Authorize]
        [HttpPatch("Change_Password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            await _authService.ChangePassword(model);
            return Ok(BaseResponse<string>.OkResponse("Thay đổi mật khẩu thành công!"));
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            AuthResponse? result = await _authService.RefreshToken(model);
            return Ok(BaseResponse<AuthResponse>.OkResponse(result));
        }

        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(EmailModelView model)
        {
            await _authService.ForgotPassword(model);
            return Ok(BaseResponse<string>.OkResponse("Đã gửi email xác nhận yêu cầu thay đổi mật khẩu."));
        }

        [HttpPatch("Confirm_OTP_ResetPassword")]
        public async Task<IActionResult> ConfirmOTPResetPassword(ConfirmOTPModel model)
        {
            await _authService.VerifyOtp(model, true);
            return Ok(BaseResponse<string>.OkResponse("Xác nhận thay đổi mật khẩu thành công!"));
        }

        [HttpPatch("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            await _authService.ResetPassword(model);
            return Ok(BaseResponse<string>.OkResponse("Đã đặt lại mật khẩu thành công!"));
        }

        [HttpPost("signin-google")]
        public async Task<IActionResult> LoginGoogle([FromBody] TokenGoogleModel tokenGoogle)
        {
            AuthResponse? result = await _authService.LoginGoogle(tokenGoogle);
            return Ok(BaseResponse<AuthResponse>.OkResponse(result));
        }

    }
}
