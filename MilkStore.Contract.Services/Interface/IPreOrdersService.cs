using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.PreOrdersModelView;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IPreOrdersService
    {
        Task<IEnumerable<PreOrders>> GetPreOrders(string? id, int page, int pageSize);
        Task CreatePreOrders(PreOrdersModelView preOrdersModel);
        //Task UpdatePreOrders(string id, PreOrdersModelView preOrdersModel);
        Task DeletePreOrders(string id);
    }
}
