namespace MilkStore.API.Controllers;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.ModelViews.RoleModelView;

[ApiController]
[Route("api/[controller]")]
public class RoleController(IRoleService roleService) : ControllerBase
{
    private readonly IRoleService _roleService = roleService;
    [HttpGet("Get_Roles")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetRoles()
    {
        IEnumerable<RoleViewModel> roles = await _roleService.GetRoles();
        return Ok(BaseResponse<IEnumerable<RoleViewModel>>.OkResponse(roles));
    }
}