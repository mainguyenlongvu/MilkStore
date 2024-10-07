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
            return Ok(BaseResponse<string>.OkResponse("Register success! Please check your email."));
        }

        [HttpPatch("Confirm_Email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmOTPModel confirmOTPModel)
        {
            await _authService.VerifyOtp(confirmOTPModel, false);
            return Ok(BaseResponse<string>.OkResponse("Confirm email success!"));
        }

        [HttpPatch("Resend_Confirmation_Email")]
        public async Task<IActionResult> ResendConfirmationEmail(EmailModelView model)
        {
            await _authService.ResendConfirmationEmail(model);
            return Ok(BaseResponse<string>.OkResponse("Email has been sent again!"));
        }

        [Authorize]
        [HttpPatch("Change_Password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            await _authService.ChangePassword(model);
            return Ok(BaseResponse<string>.OkResponse("Change password success"));
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
            return Ok(BaseResponse<string>.OkResponse(" Email change password has been sent!"));
        }

        [HttpPatch("Confirm_OTP_ResetPassword")]
        public async Task<IActionResult> ConfirmOTPResetPassword(ConfirmOTPModel model)
        {
            await _authService.VerifyOtp(model, true);
            return Ok(BaseResponse<string>.OkResponse("Confirm OTP success!"));
        }

        [HttpPatch("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            await _authService.ResetPassword(model);
            return Ok(BaseResponse<string>.OkResponse("Reset password success!"));
        }

        [HttpPost("signin-google")]
        public async Task<IActionResult> LoginGoogle([FromBody] TokenGoogleModel tokenGoogle)
        {
            AuthResponse? result = await _authService.LoginGoogle(tokenGoogle);
            return Ok(BaseResponse<AuthResponse>.OkResponse(result));
        }

    }
}
