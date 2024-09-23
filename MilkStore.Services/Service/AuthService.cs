using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.Repositories.Entity;
using Microsoft.AspNetCore.Identity;
using MilkStore.Core.Base;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using AutoMapper;
using Microsoft.EntityFrameworkCore;
public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> userManager;
    private readonly SignInManager<ApplicationUser> signInManager;
    private readonly IUnitOfWork unitOfWork;
    private readonly IMapper mapper;

    public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IUnitOfWork unitOfWork, IMapper mapper)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.unitOfWork = unitOfWork;
        this.mapper = mapper;
    }
    public async Task<ApplicationUser> ExistingUser(string email)
    {
        ApplicationUser? user = await userManager.FindByEmailAsync(email);
        if (user != null)
        {
            if (user.DeletedTime.HasValue)
            {
                throw new BaseException.ErrorException(400, "BadRequest", "Tài khoản đã bị xóa");
            }
            if (!await userManager.IsEmailConfirmedAsync(user))
            {
                throw new BaseException.ErrorException(400, "BadRequest", "Tài khoản chưa được xác nhận");
            }
            return user;
        }
        else
        {
            throw new BaseException.ErrorException(404, "NotFound", "Không tìm thấy người dùng");
        }
    }
    public async Task<SignInResult> CheckPassword(LoginModelView loginModel)
    {
        SignInResult result = await signInManager.PasswordSignInAsync(loginModel.Email, loginModel.Password, false, false);
        if (!result.Succeeded)
        {
            throw new BaseException.ErrorException(401, "Unauthorized", "Không đúng mật khẩu");
        }
        return result;
    }

    public async Task ChangePasswordAdmin(string id, ChangePasswordAdminModel model)
    {
        ApplicationUser? admin = await userManager.FindByIdAsync(id);
        if (admin is null)
        {
            throw new BaseException.ErrorException(404, "NotFound", "Không tìm thấy người dùng");
        }
        else
        {
            if (admin.DeletedTime.HasValue)
            {
                throw new BaseException.ErrorException(400, "BadRequest", "Tài khoản đã bị xóa");
            }
            else
            {
                IdentityResult result = await userManager.ChangePasswordAsync(admin, model.OldPassword, model.NewPassword);
                if (!result.Succeeded)
                {
                    throw new BaseException.ErrorException(500, " InternalServerError", result.Errors.FirstOrDefault()?.Description);
                }
            }
        }
    }
    public async Task<ApplicationUser> CheckRefreshToken(string refreshToken)
    {

        List<ApplicationUser>? users = await userManager.Users.ToListAsync();
        foreach (ApplicationUser user in users)
        {
            var storedToken = await userManager.GetAuthenticationTokenAsync(user, "Default", "RefreshToken");

            if (storedToken == refreshToken)
            {
                return user;
            }
        }
        throw new BaseException.ErrorException(401, "Unauthorized", "Mã xác thực không đúng");
    }

    public (string token, IEnumerable<string> roles) GenerateJwtToken(ApplicationUser user)
    {
        byte[] key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWT_KEY") ?? throw new Exception("JWT_KEY is not set"));
        List<Claim> claims = new List<Claim> {
            new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email)
        };
        IEnumerable<string> roles = userManager.GetRolesAsync(user: user).Result;
        foreach (string role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new Exception("JWT_ISSUER is not set"),
            Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new Exception("JWT_AUDIENCE is not set"),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
        return (tokenHandler.WriteToken(token), roles);
    }
    public async Task<string> GenerateRefreshToken(ApplicationUser user)
    {
        string? refreshToken = Guid.NewGuid().ToString();

        string? initToken = await userManager.GetAuthenticationTokenAsync(user, "Default", "RefreshToken");
        if (initToken is not null)
        {
            await userManager.RemoveAuthenticationTokenAsync(user, "Default", "RefreshToken");
        }
        await userManager.SetAuthenticationTokenAsync(user, "Default", "RefreshToken", refreshToken);
        return refreshToken;
    }

    public async Task<string> ForgotPassword(string email)
    {
        ApplicationUser? user = await userManager.FindByEmailAsync(email) ?? throw new BaseException.BadRequestException("BadRequest", "Vui lòng kiểm tra Email của bạn!");
        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            throw new BaseException.BadRequestException("BadRequest", "Vui lòng kiểm tra Email của bạn!");
        }
        string? token = await userManager.GeneratePasswordResetTokenAsync(user);
        return token;
    }
    public async Task ResetPassword(string email, string password, string token)
    {
        ApplicationUser? user = await userManager.FindByEmailAsync(email);
        if (user is null)
        {
            throw new BaseException.ErrorException(404, "NotFound", "Không tìm thấy người dùng");
        }
        if (!await userManager.IsEmailConfirmedAsync(user))
        {
            throw new BaseException.ErrorException(400, "BadRequest", "Vui lòng kiểm tra Email của bạn!");
        }
        IdentityResult? result = await userManager.ResetPasswordAsync(user, token, password);
        if (!result.Succeeded)
        {
            throw new BaseException.ErrorException(400, "BadRequest", result.Errors.FirstOrDefault()?.Description);
        }
    }
}