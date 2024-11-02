using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IPreOrdersService
    {
        Task<BasePaginatedList<PreOdersResponseDTO>> GetPreOders(string? id, int pageIndex, int pageSize);
        Task CreatePreOrders(PreOrdersModelView preOrdersModel);
        //Task UpdatePreOrders(string id, PreOrdersModelView preOrdersModel);
        Task DeletePreOrders(string id);
    }
}
