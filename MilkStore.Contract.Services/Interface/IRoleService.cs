using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.RoleModelView;

namespace MilkStore.Contract.Services.Interface
{
    public interface IRoleService
    {
        Task<IEnumerable<RoleViewModel>> GetRoles();
    }
}