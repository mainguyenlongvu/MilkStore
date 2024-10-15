using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IOrderService
    {
        Task<BasePaginatedList<OrderResponseDTO>> GetAsync(string? id, OrderStatus? orderStatus, PaymentStatus? paymentStatus, int pageIndex, int pageSize);
        Task AddAsync(List<string>? voucherCode, List<OrderDetails> orderItems, PaymentMethod paymentMethod, ShippingType shippingAddress);
        //Task UpdateAsync(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod);
        //Task UpdateToTalAmount(string id);
        Task DeleteAsync(string id);     
        Task SendingPaymentStatus_Mail(string? id);
        Task SendingOrderStatus_Mail(string? id);
        //Task UpdateInventoryQuantity(string orderId);
        //Task UpdateUserPoint(string orderId);
        Task UpdateOrder(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod);
    }
}
