using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.Repositories.Entity;
using Microsoft.AspNetCore.Identity;
using MilkStore.Core.Base;
using MilkStore.Contract.Repositories.Interface;
using AutoMapper;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using MilkStore.Core.Constants;
using MilkStore.Contract.Repositories.Entity;
using Microsoft.Extensions.Caching.Memory;
using Google.Apis.Auth;
using MilkStore.Contract.Services.Interface;
using Microsoft.Extensions.Configuration;
using CloudinaryDotNet.Actions;
using SQLitePCL;
namespace MilkStore.Services.Service;
public class AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
      IMapper mapper, IHttpContextAccessor httpContextAccessor,
      RoleManager<ApplicationRole> roleManager, IEmailService emailService, IMemoryCache memoryCache,
      IUnitOfWork unitOfWork, IConfiguration configuration) : IAuthService
{

    private readonly UserManager<ApplicationUser> userManager = userManager;
    private readonly SignInManager<ApplicationUser> signInManager = signInManager;
    private readonly RoleManager<ApplicationRole> roleManager = roleManager;
    private readonly IUnitOfWork unitOfWork = unitOfWork;
    private readonly IEmailService emailService = emailService;
    private readonly IMapper mapper = mapper;
    private readonly IMemoryCache memoryCache = memoryCache;
    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;
    #region Private Service
    private readonly Microsoft.Extensions.Configuration.IConfiguration configuration = configuration;
    private async Task<ApplicationUser> CheckRefreshToken(string refreshToken)
    {

        List<ApplicationUser>? users = await userManager.Users.ToListAsync();
        foreach (ApplicationUser user in users)
        {
            string? storedToken = await userManager.GetAuthenticationTokenAsync(user, "Default", "RefreshToken");

            if (storedToken == refreshToken)
            {
                return user;
            }
        }
        throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");
    }
    private (string token, IEnumerable<string> roles) GenerateJwtToken(ApplicationUser user)
    {
        string key = configuration["JwtSettings:Key"] ?? throw new Exception("JWT Key is missing in configuration");
        string issuer = configuration["JwtSettings:Issuer"] ?? throw new Exception("JWT Issuer is missing in configuration");
        string audience = configuration["JwtSettings:Audience"] ?? throw new Exception("JWT Audience is missing in configuration");

        byte[] keyBytes = Encoding.ASCII.GetBytes(key);

        List<Claim> claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email)
        };

        IEnumerable<string> roles = userManager.GetRolesAsync(user).Result;
        foreach (string role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature)
        };

        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        return (tokenHandler.WriteToken(token), roles);
    }
    private async Task<string> GenerateRefreshToken(ApplicationUser user)
    {
        DateTime now = DateTime.UtcNow;
        // Common claims for both tokens
        List<Claim> claims = new List<Claim>
    {
        new Claim("id", user.Id.ToString()),
        // assign 
        new Claim("exp", now.Ticks.ToString())
    };
        var keyString = configuration.GetSection("JwtSettings:Key").Value ?? string.Empty;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));

        var claimsIdentity = new ClaimsIdentity(claims, "Bearer");
        var principal = new ClaimsPrincipal(new[] { claimsIdentity });
        httpContextAccessor.HttpContext.User = principal;

        Console.WriteLine("Check Key:", key);
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
        // Generate refresh token
        var refreshToken = new JwtSecurityToken(
            claims: claims,
        issuer: configuration.GetSection("JwtSettings:Issuer").Value,
        audience: configuration.GetSection("JwtSettings:Audience").Value,
        expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: creds
        );
        var refreshTokenString = new JwtSecurityTokenHandler().WriteToken(refreshToken);

        string? initToken = await userManager.GetAuthenticationTokenAsync(user, "Default", "RefreshToken");
        if (initToken != null)
        {

            await userManager.RemoveAuthenticationTokenAsync(user, "Default", "RefreshToken");

        }

        await userManager.SetAuthenticationTokenAsync(user, "Default", "RefreshToken", refreshTokenString);
        return refreshTokenString;
    }
    private string GenerateOtp()
    {
        Random random = new Random();
        string otp = random.Next(100000, 999999).ToString();
        return otp;
    }
    private async Task<string> AssignMemberToStaffAsync()
    {
        IList<ApplicationUser>? staffUsers = await userManager.GetUsersInRoleAsync("Staff");
        if (staffUsers.Any())
        {
            ApplicationUser? staffWithLeastMembers = null;
            int leastMembersCount = int.MaxValue;
            foreach (ApplicationUser staff in staffUsers)
            {
                List<ApplicationUser>? members = await unitOfWork.GetRepository<ApplicationUser>().Entities.Where(u => u.ManagerId == staff.Id).ToListAsync();
                int memberCount = members.Count;
                if (memberCount < leastMembersCount)
                {
                    leastMembersCount = memberCount;
                    staffWithLeastMembers = staff;
                }
            }
            staffWithLeastMembers ??= staffUsers.First();
            return staffWithLeastMembers.Id.ToString();
        }
        else
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không tìm thấy staff");
        }

    }
    #endregion


    #region Implementation Interface
    public async Task<AuthResponse> Login(LoginModelView loginModel)
    {
        ApplicationUser? user = await userManager.FindByEmailAsync(loginModel.Email)
         ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy user");

        if (user.DeletedTime.HasValue)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Tài khoản đã bị xóa");
        }
        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Tài khoản chưa được xác nhận");
        }
        SignInResult result = await signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, false);
        if (!result.Succeeded)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Mật khẩu không đúng");
        }
        httpContextAccessor.HttpContext.Session.SetString("UserID", user.Id.ToString());
        (string token, IEnumerable<string> roles) = GenerateJwtToken(user);
        string refreshToken = await GenerateRefreshToken(user);
        return new AuthResponse
        {
            AccessToken = token,
            RefreshToken = refreshToken,
            TokenType = "JWT",
            AuthType = "Bearer",
            ExpiresIn = DateTime.UtcNow.AddHours(1),
            User = new UserInfo
            {
                Email = user.Email,
                Roles = roles.ToList()
            }
        };

    }
    public async Task Register(RegisterModelView registerModelView)
    {
        ApplicationUser? user = await userManager.FindByNameAsync(registerModelView.Email);
        if (user != null)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Email đã tồn tại");
        }
        ApplicationUser? newUser = mapper.Map<ApplicationUser>(registerModelView);

        newUser.UserName = registerModelView.Email;

        string ManagerId = await AssignMemberToStaffAsync();
        string OTP = GenerateOtp();
        newUser.EmailCode = OTP;
        newUser.ManagerId = Guid.Parse(ManagerId);
        newUser.Name = registerModelView.Name;

        IdentityResult? result = await userManager.CreateAsync(newUser, registerModelView.Password);
        if (result.Succeeded)
        {
            bool roleExist = await roleManager.RoleExistsAsync("Member");
            if (!roleExist)
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = "Member" });
            }
            await userManager.AddToRoleAsync(newUser, "Member");

            await emailService.SendEmailAsync(registerModelView.Email, "Xác nhận tài khoản",
                       $"Vui lòng xác nhận tài khoản của bạn, OTP của bạn là:  <div class='otp'>{OTP}</div>");
        }
        else
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.ServerError, ErrorCode.ServerError, $"Error when creating user {result.Errors.FirstOrDefault()?.Description}");
        }
    }
    public async Task VerifyOtp(ConfirmOTPModel model, bool isResetPassword)
    {
        var user = await unitOfWork.GetRepository<ApplicationUser>().Entities.FirstOrDefaultAsync(x => x.Email == model.Email && !x.DeletedTime.HasValue) ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không tìm thấy mail");


        if (user.EmailCode == model.OTP)
        {
            user.EmailConfirmed = true;
            await unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await unitOfWork.SaveAsync();
        }
        else
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "OTP không hợp lệ hoặc đã hết hạn");
        }
    }

    public async Task ResendConfirmationEmail(EmailModelView emailModelView)
    {
        if (string.IsNullOrWhiteSpace(emailModelView.Email))
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Email không được để trống!");
        }

        var user = await unitOfWork.GetRepository<ApplicationUser>().Entities.FirstOrDefaultAsync(x => x.Email == emailModelView.Email && !x.DeletedTime.HasValue) ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không tìm thấy Email");

        string OTP = GenerateOtp();
        user.EmailCode = OTP;
        await unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
        await unitOfWork.SaveAsync();
        await emailService.SendEmailAsync(emailModelView.Email, "Xác nhận tài khoản",
                   $"Vui lòng xác nhận tài khoản của bạn, OTP của bạn là:  <div class='otp'>{OTP}</div>");
    }
    public async Task ChangePassword(ChangePasswordModel model)
    {
        string? userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");
        ApplicationUser? admin = await userManager.FindByIdAsync(userId) ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy user");
        if (admin.DeletedTime.HasValue)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Tài khoản đã bị xóa");
        }
        else
        {
            IdentityResult result = await userManager.ChangePasswordAsync(admin, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.ServerError, ErrorCode.ServerError, result.Errors.FirstOrDefault()?.Description);
            }
        }

    }
    public async Task<AuthResponse> RefreshToken(RefreshTokenModel refreshTokenModel)
    {
        ApplicationUser? user = await CheckRefreshToken(refreshTokenModel.refreshToken);
        (string token, IEnumerable<string> roles) = GenerateJwtToken(user);
        string refreshToken = await GenerateRefreshToken(user);
        return new AuthResponse
        {
            AccessToken = token,
            RefreshToken = refreshToken,
            TokenType = "JWT",
            AuthType = "Bearer",
            ExpiresIn = DateTime.UtcNow.AddHours(1),
            User = new UserInfo
            {
                Email = user.Email,
                Roles = roles.ToList()
            }
        };
    }

    public async Task ForgotPassword(EmailModelView emailModelView)
    {
        var user = await unitOfWork.GetRepository<ApplicationUser>().Entities.FirstOrDefaultAsync(x => x.Email == emailModelView.Email && !x.DeletedTime.HasValue) ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không tìm thấy mail");

        string OTP = GenerateOtp();
        user.Email = OTP;
        await unitOfWork.GetRepository < ApplicationUser >().UpdateAsync(user);
        await unitOfWork.SaveAsync();
        await emailService.SendEmailAsync(emailModelView.Email, "Đặt lại mật khẩu",
                   $"Vui lòng xác nhận tài khoản của bạn, OTP của bạn là:  <div class='otp'>{OTP}</div>");
    }
    public async Task ResetPassword(ResetPasswordModel resetPasswordModel)
    {
        var user = await unitOfWork.GetRepository<ApplicationUser>().Entities.FirstOrDefaultAsync(x => x.Email == resetPasswordModel.Email && !x.DeletedTime.HasValue) ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không tìm thấy mail");
        string? token = await userManager.GeneratePasswordResetTokenAsync(user);
        IdentityResult? result = await userManager.ResetPasswordAsync(user, token, resetPasswordModel.Password);
        if (!result.Succeeded)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, result.Errors.FirstOrDefault()?.Description);
        }
    }


    public async Task<AuthResponse> LoginGoogle(TokenGoogleModel googleModel)
    {
        GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(googleModel.token);
        string email = payload.Email;
        string providerKey = payload.Subject;
        ApplicationUser? user = await userManager.FindByEmailAsync(email);
        if (user is not null)
        {
            if (user.DeletedTime.HasValue)
            {
                throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Tài khoản đã bị xóa");
            }
        }
        else
        {
            user = mapper.Map<ApplicationUser>(new { email });
            user.UserName = email;
            IdentityResult? result = await userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                string roleName = "Member";
                bool roleExist = await roleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
                }
                await userManager.AddToRoleAsync(user, roleName);
                UserLoginInfo? userInfoLogin = new("Google", providerKey, "Google");
                IdentityResult loginResult = await userManager.AddLoginAsync(user, userInfoLogin);
                if (!loginResult.Succeeded)
                {
                    throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.ServerError, ErrorCode.ServerError, $"Error when created user {loginResult.Errors.FirstOrDefault()?.Description}");
                }
            }
            else
            {
                throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.ServerError, ErrorCode.ServerError, $"Error when created user {result.Errors.FirstOrDefault()?.Description}");
            }
        }
        (string token, IEnumerable<string> roles) = GenerateJwtToken(user);
        string refreshToken = await GenerateRefreshToken(user);
        return new AuthResponse
        {
            AccessToken = token,
            RefreshToken = refreshToken,
            TokenType = "JWT",
            AuthType = "Bearer",
            ExpiresIn = DateTime.UtcNow.AddHours(1),
            User = new UserInfo
            {
                Email = user.Email,
                Roles = roles.ToList()
            }
        };
    }
    #endregion
}