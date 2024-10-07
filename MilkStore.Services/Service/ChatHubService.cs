using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.Repositories.Entity;

public class ChatHubService(IHttpContextAccessor httpContextAccessor, UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
{
    private readonly IHttpContextAccessor httpContextAccessor = httpContextAccessor;
    private readonly UserManager<ApplicationUser> userManager = userManager;

    public async Task<(string userId, string staffId)> GetUserByToken()
    {
        string userId = httpContextAccessor.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value
         ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Token is invalid.");
        ApplicationUser? user = await userManager.FindByIdAsync(userId)
         ?? throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found.");
        if (user.DeletedTime != null)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "User has been deleted");
        }
        if (!user.EmailConfirmed)
        {
            throw new BaseException.ErrorException(MilkStore.Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Email is not confirmed");
        }
        return (userId, user.ManagerId.ToString() ?? string.Empty);
    }
    public string GetGroupName(string staffId, string memberId)
    {
        return $"ChatGroup_{staffId}_{memberId}";
    }

}