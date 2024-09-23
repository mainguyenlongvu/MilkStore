using System.Security.Policy;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;


namespace MilkStore.Services.Service
{
    public class UserService : IUserService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<ApplicationRole> roleManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IMapper _mapper;
        public UserService(UserManager<ApplicationUser> userManager, RoleManager<ApplicationRole> roleManager, IUnitOfWork unitOfWork, SignInManager<ApplicationUser> signInManager, IMapper mapper)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.signInManager = signInManager;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
        public async Task GetUserByEmailToRegister(string email)
        {
            ApplicationUser? user = await userManager.FindByNameAsync(email);
            if (user != null)
            {
                throw new BaseException.ErrorException(400, "BadRequest", "Email đã tồn tại!");
            }
        }
        public async Task<(string token, string userId)> CreateUser(RegisterModelView userModel)
        {
            ApplicationUser? newUser = new ApplicationUser
            {
                UserName = userModel.Email,
                Email = userModel.Email,
                PhoneNumber = userModel.PhoneNumber
            };

            IdentityResult? result = await userManager.CreateAsync(newUser, userModel.Password);
            if (result.Succeeded)
            {
                bool roleExist = await roleManager.RoleExistsAsync("Member");
                if (!roleExist)
                {
                    await roleManager.CreateAsync(new ApplicationRole { Name = "Member" });
                }
                await userManager.AddToRoleAsync(newUser, "Member");
                string token = await CreateToken(newUser);
                return (token, newUser.Id.ToString());
            }
            else
            {
                throw new BaseException.ErrorException(500, "InternalServerError", $"Lỗi khi tạo người dùng {result.Errors.FirstOrDefault()?.Description}");
            }
        }

        private async Task<string> CreateToken(ApplicationUser user)
        {
            return await userManager.GenerateEmailConfirmationTokenAsync(user);
        }
        public async Task<(ApplicationUser user, string token)> ResendConfirmationEmail(string email)
        {
            ApplicationUser? user = await userManager.FindByEmailAsync(email) ??
                 throw new BaseException.ErrorException(404, "NotFound", "Không tìm thấy người dùng");
            if (await userManager.IsEmailConfirmedAsync(user))
            {
                throw new BaseException.ErrorException(400, "BadRequest", "Email đã được xác nhận");
            }
            string token = await CreateToken(user);
            return (user, token);
        }
        public async Task ConfirmEmail(string email, string token)
        {
            ApplicationUser? user = await userManager.FindByEmailAsync(email) ?? throw new BaseException.ErrorException(400, "BadRequest", "Người dùng không tồn tại.");
            IdentityResult? result = await userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                throw new BaseException.ErrorException(400, "BadRequest", result.ToString());
            }
        }
        public async Task<ApplicationUser> CreateUserLoginGoogle(LoginGoogleModel loginGoogleModel)
        {
            ApplicationUser? user = await userManager.FindByEmailAsync(loginGoogleModel.Gmail);
            if (user is not null)
            {
                if (user.DeletedTime.HasValue)
                {
                    throw new BaseException.ErrorException(400, "BadRequest", "Tài khoản đã bị xóa");
                }
                else
                {
                    return user;
                }
            }
            else
            {
                ApplicationUser? newUser = _mapper.Map<ApplicationUser>(loginGoogleModel);
                newUser.UserName = loginGoogleModel.Gmail;
                IdentityResult? result = await userManager.CreateAsync(newUser);
                if (result.Succeeded)
                {
                    string roleName = "Member";
                    bool roleExist = await roleManager.RoleExistsAsync(roleName);
                    if (!roleExist)
                    {
                        await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
                    }
                    await userManager.AddToRoleAsync(newUser, roleName);
                    UserLoginInfo? userInfoLogin = new("Google", loginGoogleModel.ProviderKey, "Google");
                    IdentityResult loginResult = await userManager.AddLoginAsync(newUser, userInfoLogin);
                    if (!loginResult.Succeeded)
                    {
                        throw new BaseException.ErrorException(500, "InternalServerError", $"Lỗi khi tạo người dùng {loginResult.Errors.FirstOrDefault()?.Description}");
                    }
                }
                else
                {
                    throw new BaseException.ErrorException(505, "InternalServerError", $"Lỗi khi tạo người dùng {result.Errors.FirstOrDefault()?.Description}");
                }
                return newUser;
            }
        }
        // Cập nhật thông tin người dùng
        public async Task<ApplicationUser> UpdateUser(Guid id, UserModelView userModel, string updatedBy)
        {
            if (string.IsNullOrWhiteSpace(id.ToString()))
            {
                throw new KeyNotFoundException("User ID cannot be null, empty, or contain only whitespace.");
            }

            var user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(id)
              ?? throw new KeyNotFoundException($"User with ID {id} was not found.");

            _mapper.Map(userModel, user);

            // Gán các trường không được ánh xạ bởi AutoMapper
            user.LastUpdatedTime = CoreHelper.SystemTimeNow;
            user.LastUpdatedBy = updatedBy;


            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();

            return user;
        }




        // Xóa người dùng
        public async Task<ApplicationUser> DeleteUser(Guid userId, string deleteby)
        {
            if (string.IsNullOrWhiteSpace(userId.ToString()))
            {
                throw new KeyNotFoundException("User ID cannot be null, empty, or contain only whitespace.");
            }
            var user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(userId)
                ?? throw new KeyNotFoundException("User does not exist or has already been deleted.");

            if (user.DeletedTime.HasValue)
            {
                throw new KeyNotFoundException("User does not exist or has already been deleted.");
            }


            user.DeletedTime = DateTimeOffset.UtcNow;
            user.DeletedBy = deleteby;

            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();

            return user;
        }

        // Lấy thông tin người dùng theo ID
        public async Task<IEnumerable<UserResponeseDTO>> GetUser(string? id, int index = 1, int pageSize = 10)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                IQueryable<ApplicationUser> usersQuery = _unitOfWork.GetRepository<ApplicationUser>().Entities
                    .Where(u => u.DeletedTime == null);

                var paginatedUsers = await _unitOfWork.GetRepository<ApplicationUser>().GetPagging(usersQuery, index, pageSize);

                List<UserResponeseDTO> userResponseDtos = paginatedUsers.Items
                    .Select(MapToUserResponseDto)
                    .ToList();

                return userResponseDtos;
            }
            else
            {
                ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().Entities
                    .FirstOrDefaultAsync(u => u.Id.ToString() == id && u.DeletedTime == null)
                    ?? throw new KeyNotFoundException($"User with ID {id} was not found.");

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
                Points = user.Points,
                CreatedBy = user.CreatedBy,
                DeletedBy = user.DeletedBy,
                LastUpdatedTime = user.LastUpdatedTime,
                CreatedTime = user.CreatedTime,

            };
        }
        public async Task<ApplicationUser> AddUser(UserModelView userModel, string createdBy)
        {
            bool emailExists = await _unitOfWork.GetRepository<ApplicationUser>().Entities
                .AnyAsync(u => u.Email == userModel.Email);

            if (emailExists)
            {
                throw new ArgumentException("Email already exists");
            }

            bool userNameExists = await _unitOfWork.GetRepository<ApplicationUser>().Entities
                .AnyAsync(u => u.UserName == userModel.UserName);

            if (userNameExists)
            {
                throw new ArgumentException("UserName already exists");
            }
            ApplicationUser newUser = _mapper.Map<ApplicationUser>(userModel);
            newUser.CreatedBy = createdBy;

            await _unitOfWork.GetRepository<ApplicationUser>().InsertAsync(newUser);
            await _unitOfWork.SaveAsync();

            return newUser;
        }

        public async Task AccumulatePoints(Guid userId, double totalAmount)
        {
            // Kiểm tra nếu totalAmount <= 0 thì không cần cộng điểm
            if (totalAmount <= 0)
            {
                return;
            }

            ApplicationUser user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(userId);
            if (user == null)
            {
                throw new KeyNotFoundException("User not found");
            }

            // Tính điểm thưởng: 10 điểm cho mỗi 10.000 VND
            int earnedPoints = (int)(totalAmount / 10000) * 10;

            user.Points += earnedPoints;

            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
        }

    }


}
