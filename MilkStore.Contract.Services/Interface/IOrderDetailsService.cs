using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IOrderDetailsService
    {
        Task<OrderDetails> CreateOrderDetails(OrderDetailsModelView model);
        Task<BasePaginatedList<OrderDetailResponseDTO>> ReadPersonalOrderDetails(string? orderId, OrderDetailStatus? orderDetailStatus, int pageIndex, int pageSize);
        Task<BasePaginatedList<OrderDetailResponseDTO>> ReadAllOrderDetails(string? orderId, string? userID, OrderDetailStatus? orderDetailStatus, int pageIndex, int pageSize);
        Task<OrderDetails> UpdateOrderDetails(string id, OrderDetailsModelView model);
        Task DeleteOrderDetails(string id);
    }
}
