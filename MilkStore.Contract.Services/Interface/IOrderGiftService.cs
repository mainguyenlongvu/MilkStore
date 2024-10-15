using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.OrderGiftModelViews;
using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IOrderGiftService
    {
        Task CreateOrderGiftAuto(OrderGiftModel orderGiftModel);
        Task<IEnumerable<OrderGiftResponseDTO>> GetOrderGift(string? id);
        Task CreateOrderGiftInputUser(string mail, OrderGiftModel orderGiftModel);
        Task UpdateOrderGift(string id, OrderGiftModel orderGiftModel, OrderGiftStatus ordergiftstatus);
        Task DeleteOrderGift(string id);
    }
}
