using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.RoleModelView;

namespace MilkStore.Services.Service;
public class RoleService(RoleManager<ApplicationRole> roleManager, IMapper mapper) : IRoleService
{
    private readonly RoleManager<ApplicationRole> roleManager = roleManager;
    private readonly IMapper _mapper = mapper;

    public async Task<IEnumerable<RoleViewModel>> GetRoles()
    {
        List<ApplicationRole>? roles = await roleManager.Roles.ToListAsync();
        return _mapper.Map<IEnumerable<RoleViewModel>>(roles);
    }

}