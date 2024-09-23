using System.Security.Claims;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.Services.EmailSettings;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService authService;
        private readonly IUserService userService;
        private readonly EmailService emailService;
        private readonly SignInManager<ApplicationUser> signInManager;
        public AuthController(IAuthService authService, IUserService userService, SignInManager<ApplicationUser> signInManager, EmailService emailService)
        {
            this.authService = authService;
            this.userService = userService;
            this.signInManager = signInManager;
            this.emailService = emailService;
        }

        [HttpPost("auth_account")]
        public async Task<IActionResult> Login(LoginModelView model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            else
            {
                try
                {
                    ApplicationUser result = await authService.ExistingUser(model.Email);
                    Microsoft.AspNetCore.Identity.SignInResult resultPassword = await authService.CheckPassword(model);
                    (string token, IEnumerable<string> roles) = authService.GenerateJwtToken(result);
                    string refreshToken = await authService.GenerateRefreshToken(result);
                    return Ok(BaseResponse<object>.OkResponse(new
                    {
                        access_token = token,
                        refreshToken,
                        token_type = "JWT",
                        auth_type = "Bearer",
                        expires_in = DateTime.UtcNow.AddHours(1),
                        user = new
                        {
                            email = result.Email,
                            role = roles
                        }
                    }));

                }
                catch (BaseException.ErrorException e)
                {

                    return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
                }
            }
        }
        [HttpPost("new_account")]
        public async Task<IActionResult> Register(RegisterModelView model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            else
            {
                try
                {
                    await userService.GetUserByEmailToRegister(model.Email);

                    (string token, string userId) = await userService.CreateUser(model);

                    string? confirmationLink = this.ConfirmationLink("ConfirmEmail", model.Email, token);

                    await emailService.SendEmailAsync(model.Email, "Xác nhận tài khoản",
                         $"Vui lòng xác nhận tài khoản của bạn bằng cách nhấp vào liên kết này: <a href='{confirmationLink}'>Xác nhận</a>");

                    return Ok(BaseResponse<string>.OkResponse("Đăng ký thành công! Vui lòng kiểm tra email để xác nhận tài khoản."));
                }
                catch (BaseException.ErrorException e)
                {

                    return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
                }
            }
        }
        private string ConfirmationLink(string action, string email, string token)
        {
            string? confirmationLink = Url.Action(action, "Auth", new { email, token }, Request.Scheme);
            return confirmationLink;
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail(EmailModelView model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            try
            {
                (ApplicationUser user, string token) = await userService.ResendConfirmationEmail(model.Email);
                string? confirmationLink = this.ConfirmationLink("ConfirmEmail", model.Email, token);
                await emailService.SendEmailAsync(model.Email, "Xác nhận tài khoản",
                     $"Vui lòng xác nhận tài khoản của bạn bằng cách nhấp vào liên kết này: <a href='{confirmationLink}'>Xác nhận</a>");

                return Ok(BaseResponse<string>.OkResponse("Email đã được gửi lại!"));
            }
            catch (BaseException.ErrorException e)
            {

                return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
            }
        }
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string email, string token)
        {
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
            {
                return BadRequest("Yêu cầu không hợp lệ.");
            }
            try
            {
                await userService.ConfirmEmail(email, token);
                return Ok(BaseResponse<string>.OkResponse("Xác nhận email thành công!"));
            }
            catch (BaseException.ErrorException e)
            {

                return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
            }
        }
        [Authorize(Roles = "Admin")]
        [HttpPatch("Change_Password_Admin")]
        public async Task<IActionResult> ChangePasswordForAdmin(ChangePasswordAdminModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.ErrorException(400, "BadRequest", ModelState.ToString()));
            }
            else
            {
                try
                {
                    string? Id = User.FindFirstValue(ClaimTypes.NameIdentifier);
                    await authService.ChangePasswordAdmin(Id, model);
                    return Ok(BaseResponse<string>.OkResponse("Đổi mật khẩu thành công"));
                }
                catch (BaseException.ErrorException ex)
                {
                    return StatusCode(ex.StatusCode, new BaseException.ErrorException(ex.StatusCode, ex.ErrorDetail.ErrorCode, ex.ErrorDetail.ErrorMessage.ToString()));

                }
            }
        }
        [HttpPost("signin-google")]
        public async Task<IActionResult> LoginGoogle([FromBody] TokenGoogleModel tokenGoogle)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.ErrorException(400, "BadRequest", ModelState.ToString()));
            }
            try
            {
                GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(tokenGoogle.token);
                string email = payload.Email;
                string providerKey = payload.Subject;
                LoginGoogleModel loginModel = new() { Gmail = email, ProviderKey = providerKey };
                try
                {
                    ApplicationUser? userLoginGoogle = await userService.CreateUserLoginGoogle(loginModel);
                    (string token, IEnumerable<string> roles) = authService.GenerateJwtToken(userLoginGoogle);
                    string refreshToken = await authService.GenerateRefreshToken(userLoginGoogle);
                    return Ok(BaseResponse<object>.OkResponse(new
                    {
                        access_token = token,
                        token_type = "JWT",
                        auth_type = "Bearer",
                        refreshToken,
                        expires_in = DateTime.UtcNow.AddHours(1),
                        user = new
                        {
                            email = userLoginGoogle.Email,
                            role = roles
                        }
                    }));
                }
                catch (BaseException.ErrorException ex)
                {
                    return StatusCode(ex.StatusCode, new BaseException.ErrorException(ex.StatusCode, ex.ErrorDetail.ErrorCode, ex.ErrorDetail.ErrorMessage.ToString()));

                }
            }
            catch
            {
                return BadRequest(new BaseException.ErrorException(400, "BadRequest", "Token không hợp lệ"));
            }
        }
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.ErrorException(400, "BadRequest", ModelState.ToString()));
            }
            else
            {
                try
                {
                    ApplicationUser? user = await authService.CheckRefreshToken(model.refreshToken);
                    (string token, IEnumerable<string> roles) = authService.GenerateJwtToken(user);
                    string refreshToken = await authService.GenerateRefreshToken(user);
                    return Ok(BaseResponse<object>.OkResponse(new
                    {
                        access_token = token,
                        token_type = "JWT",
                        auth_type = "Bearer",
                        refreshToken,
                        expires_in = DateTime.UtcNow.AddHours(1),
                        user = new
                        {
                            email = user.Email,
                            role = roles
                        }
                    }));
                }
                catch (BaseException.ErrorException ex)
                {

                    return StatusCode(ex.StatusCode, new BaseException.ErrorException(ex.StatusCode, ex.ErrorDetail.ErrorCode, ex.ErrorDetail.ErrorMessage.ToString()));
                }
            }
        }
        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(EmailModelView model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            try
            {
                string token = await authService.ForgotPassword(model.Email);
                await emailService.SendEmailAsync(model.Email, "Đặt lại mật khẩu",
                     $"Vui lòng xác nhận tài khoản của bạn bằng cách nhấp vào liên kết này: <a href='{Environment.GetEnvironmentVariable("DOMAIN")}/ForgotPassword?token={token}&email={model.Email}'>Đặt lại mật khẩu</a>");
                return Ok(BaseResponse<string>.OkResponse("Vui lòng kiểm tra email để đặt lại mật khẩu."));
            }
            catch (BaseException.ErrorException e)
            {

                return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
            }
        }
        [HttpPatch("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new BaseException.BadRequestException("BadRequest", ModelState.ToString()));
            }
            try
            {
                await authService.ResetPassword(model.Email, model.Password, model.Token);
                return Ok(BaseResponse<string>.OkResponse("Đặt lại mật khẩu thành công!"));
            }
            catch (BaseException.ErrorException e)
            {

                return StatusCode(e.StatusCode, new BaseException.ErrorException(e.StatusCode, e.ErrorDetail.ErrorCode, e.ErrorDetail.ErrorMessage.ToString()));
            }
        }

    }
}
