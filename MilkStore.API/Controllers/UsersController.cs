using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.Services.Service;
using System.Security.Claims;
namespace MilkStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly UserManager<ApplicationUser> _userManager;

        public UsersController(IUserService userService, UserManager<ApplicationUser> userManager)
        {
            _userService = userService;
            _userManager = userManager;

        }
        [HttpGet()]
        public async Task<IActionResult> GetUsers(string? id, int index = 1, int pageSize = 10)
        {
            try
            {
                IEnumerable<UserResponeseDTO> users = await _userService.GetUser(id, index, pageSize);
                return Ok(BaseResponse<IEnumerable<UserResponeseDTO>>.OkResponse(users));
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while Get the user", details = ex.Message });
            }
        }
        [HttpPost("add")]
        //[Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddUser(UserModelView userModel)
        {
            string createdBy = User?.Claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? "System";
            try
            {
                ApplicationUser newUser = await _userService.AddUser(userModel, createdBy);
                if (newUser is null)
                {
                    return BadRequest(new { message = "Failed to create user" });
                }
                return Ok(new { message = "Successfully created user" });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while creating the user.", error = ex.Message });
            }
        }

        //[HttpGet()]
        //public async Task<IActionResult> Login(int index = 1, int pageSize = 10)
        //{
        //    // IList<UserResponseModel> a = await _userService.GetAll();
        //    // return Ok(BaseResponse<IList<UserResponseModel>>.OkResponse(a));
        //    return Ok("ok");
        //}
        [HttpPut("update/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UserModelView userModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            try
            {
                string updatedBy = User.Identity?.Name ?? "System";
                ApplicationUser updatedUser = await _userService.UpdateUser(id, userModel, updatedBy);
                return Ok(new { message = "Successfully update user" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while Update the user", details = ex.Message });
            }

        }

        [HttpDelete("delete/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Delete1User(Guid userId)
        {

            try
            {
                string deleteby = User.Identity?.Name ?? "System";
                ApplicationUser deletedUser = await _userService.DeleteUser(userId, deleteby);
                return Ok(new { message = "Successfully deleted user" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while deleting the user", details = ex.Message });
            }
        }
    }
}
