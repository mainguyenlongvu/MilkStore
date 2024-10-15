using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.Core.Constants;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IUserService
    {

        Task UpdateUser(UserUpdateModelView userUpdateModelView);
        Task DeleteUser(string userId);
        Task AddUserWithRoleAsync(UserModelView userModel);
        Task AccumulatePoints(string userId, double totalAmount, OrderStatus orderStatus);
        Task<UserProfileResponseModelView> GetUserProfile();

        Task UpdateUserByAdmin(string userID, UserUpdateByAdminModel model);
        Task<BasePaginatedList<UserResponseDTO>> GetAsync(
            int? page,
            int? pageSize,
            string? name,
            string? phone,
            string? email,
            SortBy sortBy,
            SortOrder sortOrder,
            string? role,
            string? id
            );

    }
}
