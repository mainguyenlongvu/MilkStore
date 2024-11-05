using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using MilkStore.ModelViews;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Repositories.Entity;
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
        private readonly IMapper _mapper;

        public TransactionService(IUnitOfWork unitOfWork, IServiceProvider serviceProvider, IHttpContextAccessor httpContextAccessor, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _serviceProvider = serviceProvider;
            _httpContextAccessor = httpContextAccessor;
            _mapper = mapper;
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
                    .Include(or => or.OrderDetailss)
                    .Where(o => o.CreatedBy == userID && o.OrderStatuss == OrderStatus.Pending && o.PaymentStatuss == PaymentStatus.Unpaid)
                    .OrderByDescending(o => o.OrderDate)
                    .FirstOrDefaultAsync() // Lấy đơn hàng mới nhất
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");

                // Tính tổng giá trị đơn hàng               
                double totalAmount = Math.Round(order.DiscountedAmount);

                // Tạo mã hóa đơn duy nhất
                string invoiceCode = $"{shippingAddress}-checkout{DateTime.Now:yyyyMMddHHmmssfff} {order.Id}";

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
                Order order = await _unitOfWork.GetRepository<Order>().Entities
                    .Include(or => or.OrderDetailss)
                    .Where(o => o.CreatedBy == userID && o.OrderStatuss == OrderStatus.Pending && o.PaymentStatuss == PaymentStatus.Unpaid)
                    .OrderByDescending(o => o.OrderDate)
                    .FirstOrDefaultAsync() // Lấy đơn hàng mới nhất
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");

                List<OrderDetails>? orderDetails = order.OrderDetailss.Where(od => od.DeletedTime == null).ToList();
                //cập nhật trạng thái của các order detail
                orderDetails.ForEach(od => od.Status = OrderDetailStatus.Ordered);
                await _unitOfWork.GetRepository<OrderDetails>().BulkUpdateAsync(orderDetails);
                await _unitOfWork.SaveAsync();

                if(paymentMethod == PaymentMethod.UserWallet)
                {
                    var user = await _unitOfWork.GetRepository<ApplicationUser>().GetByIdAsync(Guid.Parse(userID))
                        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found");
                    if(user.Balance < order.DiscountedAmount)
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Số dư không đủ để thanh toán đơn hàng.");
                    }
                    user.Balance -= order.TotalAmount;
                    user.TransactionHistories.Add(new TransactionHistory
                    {
                        UserId = user.Id,
                        TransactionDate = DateTime.Now,
                        Type = TransactionType.UserWallet,
                        Amount = order.TotalAmount,
                        BalanceAfterTransaction = user.Balance,
                        Content = $"Thanh toán đơn hàng {order.Id}"
                    });

                    if(shippingAddress == ShippingType.InStore)
                    {
                        await _orderService.UpdateOrder(order.Id, new OrderModelView
                        {
                            ShippingAddress = order.ShippingAddress,
                        }, OrderStatus.Delivered, PaymentStatus.Paid, PaymentMethod.UserWallet);
                    }
                    else
                    {
                        await _orderService.UpdateOrder(order.Id, new OrderModelView
                        {
                            ShippingAddress = order.ShippingAddress,
                        }, OrderStatus.Pending, PaymentStatus.Paid, PaymentMethod.UserWallet);
                    }
                    
                }
                return "Đặt hàng thành công! Vui lòng kiểm tra email để theo dõi đơn hàng!";

            }
        }
        public async Task<string> Topup(double amount)
        {
            if(amount <= 0)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Số tiền không hợp lệ");
            }
            if (amount < 10000)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Số tiền nạp tối thiểu là 10.000 VND.");
            }
            string userID = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "User not found");
            var _paymentService = _serviceProvider.GetRequiredService<IPaymentService>();            

            var paymentRequest = new PaymentRequest
            {
                TotalAmount = amount,
                InvoiceCode = $"Topup{DateTime.Now:yyyyMMddHHmmssfff} {userID}",
                OrderType = "Topup",
            };

            string paymentUrl = _paymentService.CreatePayment(paymentRequest);

            return paymentUrl;
        }
        public async Task<BasePaginatedList<TransactionHistoryResponseDTO>> GetAllTransactionHistoryAsync(string? userId, TransactionType? transactionType,DateTime? fromDate,DateTime? toDate,int? month,int? year,int pageIndex,int pageSize)
        {
            // Bắt đầu truy vấn từ bảng Transaction với điều kiện không bị xóa và người dùng phù hợp
            IQueryable<TransactionHistory>? query = _unitOfWork.GetRepository<TransactionHistory>()
                .Entities
                .AsNoTracking()
                .Where(transaction => transaction.DeletedTime == null);
            if(!string.IsNullOrWhiteSpace(userId))
            {
                query = query.Where(transaction => transaction.UserId == Guid.Parse(userId));
            }
            // Lọc theo loại giao dịch (TransactionType)
            if (transactionType.HasValue)
            {
                query = query.Where(transaction => transaction.Type == transactionType.Value);
            }

            // Lọc theo khoảng thời gian (từ ngày - đến ngày)
            if (fromDate.HasValue)
            {
                query = query.Where(transaction => transaction.TransactionDate >= fromDate.Value);
            }

            if (toDate.HasValue)
            {
                query = query.Where(transaction => transaction.TransactionDate <= toDate.Value);
            }

            // Lọc theo tháng
            if (month.HasValue)
            {
                query = query.Where(transaction => transaction.TransactionDate.Month == month.Value);
            }

            // Lọc theo năm
            if (year.HasValue)
            {
                query = query.Where(transaction => transaction.TransactionDate.Year == year.Value);
            }

            // Phân trang kết quả truy vấn
            BasePaginatedList<TransactionHistory>? paginatedTransactions = await _unitOfWork.GetRepository<TransactionHistory>()
                .GetPagging(query, pageIndex, pageSize);

            // Trường hợp không tìm thấy giao dịch nào
            if (!paginatedTransactions.Items.Any())
            {
                return new BasePaginatedList<TransactionHistoryResponseDTO>(new List<TransactionHistoryResponseDTO>(), 0, pageIndex, pageSize);
            }

            // Ánh xạ dữ liệu từ Transaction sang TransactionHistoryResponseDTO
            List<TransactionHistoryResponseDTO>? transactionDtosResult = _mapper.Map<List<TransactionHistoryResponseDTO>>(paginatedTransactions.Items);

            // Trả về danh sách giao dịch theo phân trang
            return new BasePaginatedList<TransactionHistoryResponseDTO>(
                transactionDtosResult,
                paginatedTransactions.TotalItems,
                paginatedTransactions.CurrentPage,
                paginatedTransactions.PageSize
            );
        }
        public async Task<BasePaginatedList<TransactionHistoryResponseDTO>> GetPersonalTransactionHistory(TransactionType? transactionType, DateTime? fromDate, DateTime? toDate, int? month, int? year, int pageIndex, int pageSize)
        {
            string userID = _httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "User not found");

            return await GetAllTransactionHistoryAsync(userID, transactionType, fromDate, toDate, month, year, pageIndex, pageSize);
        }
    }
}
