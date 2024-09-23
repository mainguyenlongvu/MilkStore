using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IUserService
    {
        Task GetUserByEmailToRegister(string email);
        //Task CreateUser(RegisterModelView userModel);
        Task<(string token, string userId)> CreateUser(RegisterModelView userModel);
        Task ConfirmEmail(string userId, string token);
        Task<(ApplicationUser user, string token)> ResendConfirmationEmail(string email);
        Task<ApplicationUser> CreateUserLoginGoogle(LoginGoogleModel loginGoogleModel);
        Task<ApplicationUser> UpdateUser(Guid id, UserModelView userModel, string updatedBy);
        Task<ApplicationUser> DeleteUser(Guid userId, string deleteby);
        Task<IEnumerable<UserResponeseDTO>> GetUser(string? id, int index = 1, int pageSize = 10);
        Task<ApplicationUser> AddUser(UserModelView userModel, string createdBy);
        Task AccumulatePoints(Guid userId, double totalAmount);

    }
}
