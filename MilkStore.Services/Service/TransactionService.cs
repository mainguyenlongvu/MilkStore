using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews;
using MilkStore.ModelViews.OrderModelViews;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class TransactionService : ITransactionService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IServiceProvider _serviceProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public TransactionService(IUnitOfWork unitOfWork, IServiceProvider serviceProvider, IHttpContextAccessor httpContextAccessor)
        {
            _unitOfWork = unitOfWork;
            _serviceProvider = serviceProvider;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<string> Checkout(PaymentMethod paymentMethod, List<string>? voucherCode, ShippingType shippingAddress)
        {
            string userID = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "User not found");
            var _paymentService = _serviceProvider.GetRequiredService<IPaymentService>();
            var _orderService = _serviceProvider.GetRequiredService<IOrderService>();

            // Kiểm tra xem có giỏ hàng hiện tại không
            var cartItems = await _unitOfWork.GetRepository<OrderDetails>().Entities
                .Where(od => od.CreatedBy == userID && od.Status == OrderDetailStatus.InCart && od.DeletedTime == null)
                .Include(od => od.Products) // Bao gồm thông tin sản phẩm để tính tổng giá trị
                .ToListAsync();

            if (!cartItems.Any())
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Your cart is empty. Please add items to cart before checkout.");
            }

            
            if (paymentMethod == PaymentMethod.Online)
            {
                
                // Tạo đơn hàng
                await _orderService.AddAsync(voucherCode, cartItems, paymentMethod, shippingAddress);
                
                Order order = await _unitOfWork.GetRepository<Order>().Entities
                    .FirstOrDefaultAsync(o => o.CreatedBy == userID && o.OrderStatuss == OrderStatus.Pending && o.PaymentStatuss == PaymentStatus.Unpaid)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");

                // Tính tổng giá trị đơn hàng               
                double totalAmount = order.DiscountedAmount;

                // Tạo mã hóa đơn duy nhất
                string invoiceCode = $"HD-{DateTime.Now:yyyyMMddHHmmssfff} {order.Id}";

                var paymentRequest = new PaymentRequest
                {
                    TotalAmount = totalAmount,
                    InvoiceCode = invoiceCode,
                    OrderType = shippingAddress.ToString(),
                };

                string paymentUrl = _paymentService.CreatePayment(paymentRequest);

                return paymentUrl;

            }
            else
            {
                // Tạo đơn hàng
                await _orderService.AddAsync(voucherCode, cartItems, paymentMethod, shippingAddress);
                Order order = await _unitOfWork.GetRepository<Order>().Entities.Include(or => or.OrderDetailss)
                    .FirstOrDefaultAsync(o => o.CreatedBy == userID && o.OrderStatuss == OrderStatus.Pending && o.PaymentStatuss == PaymentStatus.Unpaid)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");

                //OrderModelView ord = new OrderModelView
                //{
                //    ShippingAddress = order.ShippingAddress,
                //};

                //if(shippingAddress == ShippingType.InStore && )
                //{
                //    await _orderService.UpdateOrder(order.Id, ord, OrderStatus.Delivered, PaymentStatus.Paid, paymentMethod);
                //    await _unitOfWork.SaveAsync();
                //}

                List<OrderDetails>? orderDetails = order.OrderDetailss.Where(od => od.DeletedTime == null).ToList();
                //cập nhật trạng thái của các order detail
                orderDetails.ForEach(od => od.Status = OrderDetailStatus.Ordered);
                await _unitOfWork.GetRepository<OrderDetails>().BulkUpdateAsync(orderDetails);
                await _unitOfWork.SaveAsync();
                return "Đặt hàng thành công! Vui lòng kiểm tra email để theo dõi đơn hàng!";
            }
        }
    }
}
