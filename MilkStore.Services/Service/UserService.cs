using System.Security.Claims;
using System.Security.Policy;
using System.Text.RegularExpressions;
using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;


namespace MilkStore.Services.Service
{
    public class UserService(IEmailService emailService, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor,
     RoleManager<ApplicationRole> roleManager, IUnitOfWork unitOfWork, SignInManager<ApplicationUser> signInManager, IMapper mapper) : IUserService
    {
        private readonly IUnitOfWork _unitOfWork = unitOfWork;
        private readonly IEmailService emailService = emailService;
        private readonly UserManager<ApplicationUser> userManager = userManager;
        private readonly RoleManager<ApplicationRole> roleManager = roleManager;
        private readonly SignInManager<ApplicationUser> signInManager = signInManager;
        private readonly IMapper _mapper = mapper;
        private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;

        // Cập nhật thông tin người dùng
        public async Task UpdateUser(UserUpdateModelView userUpdateModelView)
        {
            string? userID = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token is invalid.");
            ApplicationUser? user = await userManager.FindByIdAsync(userID)
              ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, "NotFound", $"User with ID {userID} was not found.");

            _mapper.Map<ApplicationUser>(userUpdateModelView);
            user.LastUpdatedTime = CoreHelper.SystemTimeNow;
            user.LastUpdatedBy = userID;

            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
        }

        // Xóa người dùng
        public async Task DeleteUser(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "User ID cannot be null, empty, or contain only whitespace.");
            }
            string? handleBy = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token is invalid.");
            ApplicationUser? userExists = await userManager.FindByIdAsync(userId)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User does not exist or has already been deleted.");
            userExists.DeletedTime = CoreHelper.SystemTimeNow;
            userExists.DeletedBy = handleBy;
            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(userExists);
            await _unitOfWork.SaveAsync();
        }

        // Lấy thông tin người dùng theo ID
        public async Task<IEnumerable<UserResponeseDTO>> GetUser(string? id, int index = 1, int pageSize = 10)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                IQueryable<ApplicationUser> usersQuery = _unitOfWork.GetRepository<ApplicationUser>().Entities
                    .Where(u => u.DeletedTime == null);

                BasePaginatedList<ApplicationUser>? paginatedUsers = await _unitOfWork.GetRepository<ApplicationUser>().GetPagging(usersQuery, index, pageSize);

                List<UserResponeseDTO> userResponseDtos = paginatedUsers.Items
                    .Select(MapToUserResponseDto)
                    .ToList();

                return userResponseDtos;
            }
            else
            {
                ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().Entities
                    .FirstOrDefaultAsync(u => u.Id.ToString() == id && u.DeletedTime == null)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"User with ID {id} was not found.");

                return new List<UserResponeseDTO> { MapToUserResponseDto(user) };
            }
        }


        private UserResponeseDTO MapToUserResponseDto(ApplicationUser user)
        {
            return new UserResponeseDTO
            {
                Id = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                Name = user.Name,
                Points = user.Points,
                CreatedBy = user.CreatedBy,
                DeletedBy = user.DeletedBy,
                LastUpdatedTime = user.LastUpdatedTime,
                CreatedTime = user.CreatedTime,

            };
        }
        private readonly Random random = new Random();

        private string GenerateRandomPassword(int length = 8)
        {
            const string upperCaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowerCaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string specialChars = "@$!%*?&.";


            if (length < 8)
            {
                length = 8;
            }


            char[] passwordChars = new char[length];
            passwordChars[0] = upperCaseChars[random.Next(upperCaseChars.Length)];
            passwordChars[1] = lowerCaseChars[random.Next(lowerCaseChars.Length)];
            passwordChars[2] = numbers[random.Next(numbers.Length)];
            passwordChars[3] = specialChars[random.Next(specialChars.Length)];


            for (int i = 4; i < length; i++)
            {
                string allChars = upperCaseChars + lowerCaseChars + numbers + specialChars;
                passwordChars[i] = allChars[random.Next(allChars.Length)];
            }

            string password = new string(passwordChars.OrderBy(x => random.Next()).ToArray());


            if (!IsPasswordValid(password))
            {

                return GenerateRandomPassword(length);
            }

            return password;
        }

        private bool IsPasswordValid(string password)
        {
            Regex? regex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,16}$");
            return regex.IsMatch(password);
        }

        public async Task AddUserWithRoleAsync(UserModelView userModel)
        {
            string? handleBy = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token is invalid.");

            ApplicationUser? userExists = await userManager.FindByEmailAsync(userModel.Email);
            if (userExists != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Email already exists");
            }
            ApplicationUser? newUser = _mapper.Map<ApplicationUser>(userModel);
            newUser.CreatedBy = handleBy;
            newUser.EmailConfirmed = true;
            newUser.Name = userModel.Name;
            newUser.UserName = userModel.Email;
            string passwordChars = GenerateRandomPassword();
            IdentityResult? result = await userManager.CreateAsync(newUser, passwordChars);
            if (result.Succeeded)
            {
                ApplicationRole? role = await roleManager.FindByIdAsync(userModel.RoleID);
                await userManager.AddToRoleAsync(newUser, role.Name);
                await emailService.SendEmailAsync(userModel.Email, "Tài khoản nhân viên",
                      $"Mật khẩu của bạn là: {passwordChars}");
                await _unitOfWork.SaveAsync();
            }
            else
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, result.Errors.FirstOrDefault()?.Description);
            }

        }

        public async Task AccumulatePoints(string userId, double totalAmount)
        {
            // Kiểm tra nếu totalAmount <= 0 thì không cần cộng điểm
            if (totalAmount <= 0)
            {
                return;
            }

            ApplicationUser user = await userManager.FindByIdAsync(userId)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, "NotFound", "User not found");

            // Tính điểm thưởng: 10 điểm cho mỗi 10.000 VND
            int earnedPoints = (int)(totalAmount / 10000) * 10;

            user.Points += earnedPoints;

            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
        }


        public async Task<UserProfileResponseModelView> GetUserProfile()
        {
            string? userIdToken = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token is invalid.");

            ApplicationUser? user = await userManager.FindByIdAsync(userIdToken)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found.");

            UserProfileResponseModelView? userResponse = _mapper.Map<UserProfileResponseModelView>(user);

            return userResponse;

        }

    }


}
