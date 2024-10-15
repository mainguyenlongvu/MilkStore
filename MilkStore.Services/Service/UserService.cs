using System.Security.Claims;
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
        private readonly IUnitOfWork unitOfWork = unitOfWork;
        private readonly UserManager<ApplicationUser> userManager = userManager;
        private readonly RoleManager<ApplicationRole> roleManager = roleManager;
        private readonly SignInManager<ApplicationUser> signInManager = signInManager;
        private readonly IMapper _mapper = mapper;
        private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;

        // Cập nhật thông tin người dùng
        public async Task UpdateUser(UserUpdateModelView userUpdateModelView)
        {
            string? userID = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                         ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");
            ApplicationUser? user = await userManager.FindByIdAsync(userID)
              ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, "NotFound", $"Người dùng với id {userID} không tồn tại");

            _mapper.Map(userUpdateModelView, user);
            user.LastUpdatedTime = CoreHelper.SystemTimeNow;
            user.LastUpdatedBy = userID;
            user.UserName = userUpdateModelView.Email;

            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
        }

        // Xóa người dùng
        public async Task DeleteUser(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "User ID không được để trống, trống hoặc chỉ chứa các ký tự không hợp lệ");
            }
            string? handleBy = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");
            ApplicationUser? userExists = await userManager.FindByIdAsync(userId)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Người dùng không tồn tại hoặc đã bị xóa");
            userExists.DeletedTime = CoreHelper.SystemTimeNow;
            userExists.DeletedBy = handleBy;
            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(userExists);
            await _unitOfWork.SaveAsync();
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
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");

            ApplicationUser? userExists = await userManager.FindByEmailAsync(userModel.Email);
            if (userExists != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Email đã tồn tại");
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

        public async Task AccumulatePoints(string userId, double totalAmount, OrderStatus orderStatus)
        {
            // Kiểm tra nếu totalAmount <= 0 thì không cần cộng điểm
            if (totalAmount <= 0)
            {
                return;
            }

            ApplicationUser user = await userManager.FindByIdAsync(userId)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, "NotFound", "Không tìm thấy người dùng");

            // Tính điểm thưởng: 10 điểm cho mỗi 10.000 VND
            int Points = (int)(totalAmount / 10000) * 10;
            if(user.Points > 0 && orderStatus == OrderStatus.Refunded)
            {
                user.Points -= Points;
            }
            else
            {
                user.Points += Points;
            }
            await _unitOfWork.GetRepository<ApplicationUser>().UpdateAsync(user);
            await _unitOfWork.SaveAsync();
        }


        public async Task<UserProfileResponseModelView> GetUserProfile()
        {
            string? userIdToken = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");

            ApplicationUser? user = await userManager.FindByIdAsync(userIdToken)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy người dùng");

            UserProfileResponseModelView? userResponse = _mapper.Map<UserProfileResponseModelView>(user);

            return userResponse;
        }


        public async Task UpdateUserByAdmin(string userID, UserUpdateByAdminModel model)
        {
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "User ID không được để trống, trống hoặc chỉ chứa các ký tự không hợp lệ");
            }

            string? handleBy = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token không hợp lệ");
            ApplicationUser? userExists = await userManager.FindByIdAsync(userID)
             ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Người dùng không tồn tại hoặc đã bị xóa");

            _mapper.Map(model, userExists);

            userExists.UserName = model.Email;
            userExists.LastUpdatedBy = handleBy;

            if (!string.IsNullOrEmpty(model.Password))
            {
                string? passwordResetToken = await userManager.GeneratePasswordResetTokenAsync(userExists);
                IdentityResult? result = await userManager.ResetPasswordAsync(userExists, passwordResetToken, model.Password);
                if (!result.Succeeded)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không thể cập nhật mật khẩu");
                }
            }

            IdentityResult? updateResult = await userManager.UpdateAsync(userExists);
            if (!updateResult.Succeeded)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không thể cập nhật người dùng");
            }
        }
        private IQueryable<ApplicationUser> FilterUsers(
            IQueryable<ApplicationUser> query,
            string? name,
            string? phone,
            string? email,
            string? role)
        {
            if (!string.IsNullOrEmpty(name))
            {
                query = query.Where(u => u.Name.Contains(name));
            }

            if (!string.IsNullOrEmpty(phone))
            {
                query = query.Where(u => u.PhoneNumber.Contains(phone));
            }

            if (!string.IsNullOrEmpty(email))
            {
                query = query.Where(u => u.Email.Contains(email));
            }

            if (!string.IsNullOrEmpty(role))
            {
                IList<ApplicationUser>? usersInRole = userManager.GetUsersInRoleAsync(role).Result;
                query = query.Where(u => usersInRole.Contains(u));
            }

            return query;
        }
        private IQueryable<ApplicationUser> SortUsers(IQueryable<ApplicationUser> query,
            SortBy sortBy,
            SortOrder sortOrder)
        {

            switch (sortBy)
            {
                case SortBy.Name:
                    query = sortOrder == SortOrder.asc
                        ? query.OrderBy(u => u.Name)
                        : query.OrderByDescending(u => u.Name);
                    break;

                case SortBy.Email:
                    query = sortOrder == SortOrder.asc
                        ? query.OrderBy(u => u.Email)
                        : query.OrderByDescending(u => u.Email);
                    break;

                case SortBy.PhoneNumber:
                    query = sortOrder == SortOrder.asc
                        ? query.OrderBy(u => u.PhoneNumber)
                        : query.OrderByDescending(u => u.PhoneNumber);
                    break;

                case SortBy.RoleName:
                    query = sortOrder == SortOrder.asc
                        ? query.OrderBy(u => u.UserRoles.FirstOrDefault().Role.Name)
                        : query.OrderByDescending(u => u.UserRoles.FirstOrDefault().Role.Name);
                    break;

                case SortBy.CreatedDate:
                    query = sortOrder == SortOrder.asc
                        ? query.OrderBy(u => u.CreatedTime)
                        : query.OrderByDescending(u => u.CreatedTime);
                    break;

                default:
                    break;
            }


            return query;
        }
        private async Task<BasePaginatedList<UserResponseDTO>> PaginateUsers(
        IQueryable<ApplicationUser> query,
        int? page,
        int? pageSize)
        {
            int currentPage = page ?? 1;
            int currentPageSize = pageSize ?? 10;
            int totalItems = await query.CountAsync();

            List<UserResponseDTO>? users = await query
                .Skip((currentPage - 1) * currentPageSize)
                .Take(currentPageSize)
                .Select(u => new UserResponseDTO
                {
                    Id = u.Id,
                    Name = u.Name,
                    Email = u.Email,
                    PhoneNumber = u.PhoneNumber,
                    RoleName = u.UserRoles.FirstOrDefault().Role.Name,
                    CreatedBy = u.CreatedBy,
                    LastUpdatedBy = u.LastUpdatedBy,
                    DeletedBy = u.DeletedBy,
                    CreatedTime = u.CreatedTime,
                    LastUpdatedTime = u.LastUpdatedTime,
                    DeletedTime = u.DeletedTime
                })
                .ToListAsync();

            return new BasePaginatedList<UserResponseDTO>(users, totalItems, currentPage, currentPageSize);
        }


        public async Task<BasePaginatedList<UserResponseDTO>> GetAsync(
            int? page,
            int? pageSize,
            string? name,
            string? phone,
            string? email,
            SortBy sortBy,
            SortOrder sortOrder,
            string? role,
            string? id
            )
        {
            IQueryable<ApplicationUser>? query = userManager.Users.AsQueryable();
            query = query.Where(u => u.DeletedTime == null);
            if (!string.IsNullOrEmpty(id))
            {
                query = query.Where(u => u.Id == Guid.Parse(id));
            }

            query = FilterUsers(query, name, phone, email, role);
            query = SortUsers(query, sortBy, sortOrder);

            return await PaginateUsers(query, page, pageSize);
        }

    }


}
