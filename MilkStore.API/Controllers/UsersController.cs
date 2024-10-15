using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;

namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController(IUserService userService) : ControllerBase
    {
        private readonly IUserService _userService = userService;

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddUserWithRoleAsync(UserModelView userModel)
        {
            await _userService.AddUserWithRoleAsync(userModel);
            return Ok(BaseResponse<object>.OkResponse("Create user successfully"));
        }

        [HttpPut]
        [Authorize]
        public async Task<IActionResult> UpdateUser([FromBody] UserUpdateModelView userModel)
        {
            await _userService.UpdateUser(userModel);
            return Ok(BaseResponse<object>.OkResponse("Update user successfully"));
        }

        [HttpPatch("Admin_Update")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUserByAdmin([FromQuery] string userId, [FromBody] UserUpdateByAdminModel userModel)
        {
            await _userService.UpdateUserByAdmin(userId, userModel);
            return Ok(BaseResponse<object>.OkResponse("Update user successfully"));
        }

        [HttpDelete]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteOneUser([FromQuery] string userId)
        {

            await _userService.DeleteUser(userId);
            return Ok(BaseResponse<object>.OkResponse("Delete user successfully"));
        }


        [HttpGet("Profile")]
        [Authorize]
        public async Task<IActionResult> GetUserProfile()
        {
            UserProfileResponseModelView? userProfile = await _userService.GetUserProfile();
            return Ok(BaseResponse<UserProfileResponseModelView>.OkResponse(userProfile));
        }
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Get(
            [FromQuery] int? page = 1,
            [FromQuery] int? pageSize = 10,
            [FromQuery] string? SearchByName = null,
            [FromQuery] string? SearchByPhoneNumber = null,
            [FromQuery] string? SearchByEmail = null,
            [FromQuery] SortBy sortBy = SortBy.Name,
            [FromQuery] SortOrder sortOrder = SortOrder.asc,
            [FromQuery] string? role = null,
            [FromQuery] string? id = null
        )
        {
            BasePaginatedList<UserResponseDTO>? result = await _userService.GetAsync(page, pageSize, SearchByName, SearchByPhoneNumber, SearchByEmail, sortBy, sortOrder, role, id);
            return Ok(BaseResponse<BasePaginatedList<UserResponseDTO>>.OkResponse(result));
        }
    }
}
