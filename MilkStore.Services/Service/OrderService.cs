using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Core.Utils;
using Microsoft.EntityFrameworkCore;
using MilkStore.ModelViews.ResponseDTO;
using AutoMapper;
using MilkStore.Repositories.Entity;
using Microsoft.AspNetCore.Identity;
using MilkStore.Core;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using MilkStore.Core.Base;
using MilkStore.Core.Constants;
using PaymentStatus = MilkStore.Contract.Repositories.Entity.PaymentStatus;
using PaymentMethod = MilkStore.Contract.Repositories.Entity.PaymentMethod;
using OrderStatus = MilkStore.Contract.Repositories.Entity.OrderStatus;
using ShippingType = MilkStore.ModelViews.OrderModelViews.ShippingType;
using MilkStore.ModelViews.CustomerModelViews;

namespace MilkStore.Services.Service
{
    public class OrderService : IOrderService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserService _userService;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;                    
        public OrderService(IUnitOfWork unitOfWork, IMapper mapper, IEmailService emailService, UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor, IUserService userService)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _emailService = emailService;
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
            _userService = userService;                        
        }
        private string GetCurrentUserId()
        {
            string? userID = _httpContextAccessor.HttpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrWhiteSpace(userID))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Vui lòng đăng nhập!");
            }
            return userID;
        }
        public string GetUserIdFromSession()
        {
            return _httpContextAccessor.HttpContext.Session.GetString("UserID") 
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.Unauthorized, ErrorCode.Unauthorized, "Vui lòng đăng nhập!");
        }        
        public async Task<BasePaginatedList<OrderResponseDTO>> GetAsync(string? id, OrderStatus? orderStatus, PaymentStatus? paymentStatus, int pageIndex, int pageSize)
        {
            IQueryable<Order>? query = _unitOfWork.GetRepository<Order>()
                .Entities
                .AsNoTracking()
                .Where(order => order.DeletedTime == null);

            if (!string.IsNullOrWhiteSpace(id))
            {
                query = query.Where(order => order.Id == id);
            }
            if (orderStatus.HasValue)
            {
                query = query.Where(order => order.OrderStatuss == orderStatus.Value);
            }
            if (paymentStatus.HasValue)
            {
                query = query.Where(order => order.PaymentStatuss == paymentStatus.Value);
            }

            BasePaginatedList<Order>? paginatedOrders = await _unitOfWork.GetRepository<Order>()
                .GetPagging(query, pageIndex, pageSize);
            
            if (!paginatedOrders.Items.Any() && !string.IsNullOrWhiteSpace(id))
            {
                Order? orderById = await query.FirstOrDefaultAsync();
                if (orderById != null)
                {
                    OrderResponseDTO? orderDto = _mapper.Map<OrderResponseDTO>(orderById);
                    return new BasePaginatedList<OrderResponseDTO>(new List<OrderResponseDTO> { orderDto }, 1, 1, 1);
                }
            }

            List<OrderResponseDTO>? orderDtosResult = _mapper.Map<List<OrderResponseDTO>>(paginatedOrders.Items);
            return new BasePaginatedList<OrderResponseDTO>(
                orderDtosResult,
                paginatedOrders.TotalItems,
                paginatedOrders.CurrentPage,
                paginatedOrders.PageSize
            );
        }


        public async Task AddAsync(List<string>? voucherCode, List<OrderDetails> orderItems, PaymentMethod paymentMethod, ShippingType shippingAddress)
        {
            string userID = GetUserIdFromSession();
            var user = await _userManager.FindByIdAsync(userID)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy người dùng");

            if (string.IsNullOrWhiteSpace(user.ShippingAddress))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Vui lòng thêm địa chỉ giao hàng trước khi thanh toán!");
            }

            string shipMethod = shippingAddress == ShippingType.InStore ? "Milk Store" : user.ShippingAddress;
            // Kiểm tra nếu giỏ hàng đang có OrderID của đơn hàng cũ
            var oldOrder = await _unitOfWork.GetRepository<Order>().Entities
                .Include(o => o.OrderDetailss)
                .FirstOrDefaultAsync(o => o.UserId == Guid.Parse(userID) && o.PaymentStatuss == PaymentStatus.Unpaid && o.OrderStatuss == OrderStatus.Pending);

            if (oldOrder != null)
            {                
                oldOrder.OrderStatuss = OrderStatus.Cancelled;
                await _unitOfWork.GetRepository<Order>().UpdateAsync(oldOrder);
                //Cập nhật lại số lượng tồn kho
                foreach (var orderDetail in oldOrder.OrderDetailss.Where(od => od.DeletedTime == null))
                {
                    var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(orderDetail.ProductID)
                        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy sản phẩm có id {orderDetail.ProductID}");

                    product.QuantityInStock += orderDetail.Quantity;
                    await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
                }
            }
            // Khởi tạo đơn hàng mới
            Order order = new Order
            {
                UserId = Guid.Parse(userID),
                CreatedBy = userID,
                OrderDate = CoreHelper.SystemTimeNow,
                estimatedDeliveryDate = $"từ {CoreHelper.SystemTimeNow.AddDays(3):dd/MM/yyyy} đến {CoreHelper.SystemTimeNow.AddDays(5):dd/MM/yyyy}",
                ShippingAddress = shipMethod,
                TotalAmount = 0,
                DiscountedAmount = 0,
                PaymentStatuss = PaymentStatus.Unpaid,
                OrderStatuss = OrderStatus.Pending,
                PaymentMethod = paymentMethod,
                OrderDetailss = orderItems
            };

            // Kiểm tra và cập nhật số lượng tồn kho cho từng sản phẩm trong orderItems
            foreach (var orderDetail in orderItems)
            {
                var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(orderDetail.ProductID)
                    ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy sản phẩm có id {orderDetail.ProductID}");

                if (product.QuantityInStock < orderDetail.Quantity)
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Không đủ số lượng sản phẩm: {product.ProductName}");
                }
                
                product.QuantityInStock -= orderDetail.Quantity;                
                await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
            }
            order.IsInventoryUpdated = true;
            // Kiểm tra và xử lý voucher
            if (voucherCode is not null && voucherCode.Count > 3)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Bạn chỉ có thể áp dụng tối đa 3 voucher.");
            }

            order.TotalAmount = orderItems.Sum(o => o.TotalAmount);
            double totalDiscount = 0;
            double discountedTotal = order.TotalAmount;
            List<string> invalidVouchers = new List<string>();

            if (voucherCode is not null && voucherCode.Any())
            {
                foreach (var voucher in voucherCode)
                {
                    Voucher vch = await _unitOfWork.GetRepository<Voucher>().Entities
                        .FirstOrDefaultAsync(v => v.VoucherCode == voucher && !v.DeletedTime.HasValue)
                        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy voucher {voucher}");

                    if (vch.ExpiryDate < order.OrderDate)
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Voucher {voucher} đã hết hạn.");
                    }

                    if (discountedTotal < Convert.ToDouble(vch.LimitSalePrice))
                    {
                        throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Tổng tiền chưa đạt điều kiện áp dụng voucher {voucher}.");
                    }

                    double discountAmount = (discountedTotal * vch.SalePercent) / 100.0;
                    discountedTotal -= discountAmount;
                    totalDiscount += discountAmount;

                    order.VoucherCode.Add(vch.VoucherCode);
                    vch.UsedCount++;
                    await _unitOfWork.GetRepository<Voucher>().UpdateAsync(vch);
                }
            }

            if (invalidVouchers.Any())
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, string.Join(", ", invalidVouchers));
            }

            order.DiscountedAmount = discountedTotal;

            await _unitOfWork.GetRepository<Order>().InsertAsync(order);
            await _unitOfWork.SaveAsync();

            orderItems.ForEach(item => item.OrderID = order.Id);
            await _unitOfWork.GetRepository<OrderDetails>().BulkUpdateAsync(orderItems); 
            await _unitOfWork.SaveAsync();
        }


        //public async Task UpdateOrder(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod)
        //{
        //    await UpdateAsync(id, ord, orderStatus, paymentStatus, paymentMethod);
        //    await SendingPaymentStatus_Mail(id);
        //    await SendingOrderStatus_Mail(id);
        //    if (orderStatus == OrderStatus.Delivered && paymentStatus == PaymentStatus.Paid || orderStatus == OrderStatus.Refunded)
        //    {
        //        await UpdateUserPoint(id);
        //    }
        //    if (orderStatus != OrderStatus.Pending || orderStatus == OrderStatus.Refunded)
        //    {
        //        await UpdateInventoryQuantity(id);
        //    }
        //}
        //public async Task UpdateOrder(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod)
        //{
        //    await UpdateAsync(id, ord, orderStatus, paymentStatus, paymentMethod);

        //    // Các tác vụ không chạm đến DbContext như gửi mail có thể thực hiện đồng thời
        //    var emailTasks = new List<Task>
        //    {
        //        SendingPaymentStatus_Mail(id),
        //        SendingOrderStatus_Mail(id)
        //    };

        //    if (orderStatus == OrderStatus.Delivered && paymentStatus == PaymentStatus.Paid || orderStatus == OrderStatus.Refunded)
        //    {
        //        await UpdateUserPoint(id);
        //    }

        //    if (orderStatus == OrderStatus.Confirmed || orderStatus == OrderStatus.Refunded)
        //    {
        //        await UpdateInventoryQuantity(id); 
        //    }

        //    await Task.WhenAll(emailTasks);
        //}
        public async Task UpdateOrder(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod)
        {
            string userID = GetUserIdFromSession();
            
            var order = await _unitOfWork.GetRepository<Order>().Entities
                .Include(o => o.OrderDetailss) // Bao gồm OrderDetails để cập nhật tồn kho
                .FirstOrDefaultAsync(o => o.Id == id && !o.DeletedTime.HasValue)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đơn hàng có ID {id} hoặc đã bị xóa.");            
            var user = await _userManager.FindByIdAsync(order.UserId.ToString())
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy người dùng");

            // Ánh xạ các thuộc tính từ ord vào order
            _mapper.Map(ord, order);

            // Cập nhật trạng thái đơn hàng
            order.OrderStatuss = orderStatus;
            order.PaymentStatuss = paymentStatus;
            order.PaymentMethod = paymentMethod;
            order.LastUpdatedTime = CoreHelper.SystemTimeNow;
            order.LastUpdatedBy = userID;

            // Cập nhật điểm người dùng nếu cần
            if (!order.IsPointAdded)
            {
                if (orderStatus == OrderStatus.Delivered && paymentStatus == PaymentStatus.Paid || orderStatus == OrderStatus.Refunded)
                {
                    await _userService.AccumulatePoints(user.Id.ToString(), order.DiscountedAmount, order.OrderStatuss);

                    order.PointsAdded = order.OrderStatuss == OrderStatus.Refunded ? 0 : (int)(order.DiscountedAmount / 10000) * 10;
                    order.IsPointAdded = true;
                }                    
            }
            /* Kiểm tra nếu hàng trả về nguyên vẹn thì cập nhật */
            if (orderStatus == OrderStatus.Refunded && order.IsInventoryUpdated)
            {
                foreach (var orderDetail in order.OrderDetailss.Where(od => od.DeletedTime == null))
                {
                    var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(orderDetail.ProductID)
                        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy sản phẩm có id {orderDetail.ProductID}");

                    product.QuantityInStock += orderDetail.Quantity; 
                    await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
                }
                //hoàn tiền
                if(order.PaymentStatuss == PaymentStatus.Paid)
                {
                    user.Balance += order.DiscountedAmount;
                    user.TransactionHistories.Add(new TransactionHistory
                    {
                        UserId = user.Id,
                        TransactionDate = CoreHelper.SystemTimeNow,
                        Type = TransactionType.UserWallet,
                        Amount = order.DiscountedAmount,
                        BalanceAfterTransaction = user.Balance,
                        Content = "Hoàn tiền đơn hàng " + order.Id
                    });

                }
            }

            // Cập nhật đơn hàng
            await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
            await _unitOfWork.SaveAsync();                        

            // Gửi email trạng thái thanh toán và đơn hàng
            await SendingPaymentStatus_Mail(id);
            await SendingOrderStatus_Mail(id);
        }
        public async Task UpdateOrderByCustomer(string id, CustomerOrderAction action, string? newShippingAddress)
        {
            string userID = GetCurrentUserId();
            //chỉ update được đơn hàng của mình
            var order = await _unitOfWork.GetRepository<Order>().Entities
                .Include(o => o.OrderDetailss)
                .FirstOrDefaultAsync(o => o.Id == id && o.UserId == Guid.Parse(userID) && !o.DeletedTime.HasValue)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đơn hàng có ID {id} hoặc bạn không có quyền truy cập.");

            // Kiểm tra trạng thái đơn hàng để xác định hành động của khách hàng
            if (action == CustomerOrderAction.ChangeShippingAddress)
            {
                // Khách hàng chỉ được phép thay đổi địa chỉ giao hàng trước khi đơn hàng được giao
                if (order.OrderStatuss == OrderStatus.Pending)
                {
                    order.ShippingAddress = newShippingAddress 
                        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Địa chỉ giao hàng không hợp lệ");
                }
                else
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Không thể thay đổi địa chỉ giao hàng khi đơn hàng đã được giao hoặc đang giao.");
                }
            }
            else if (action == CustomerOrderAction.RequestReturn)
            {
                // Khách hàng chỉ được yêu cầu trả hàng nếu đơn hàng đã được giao
                if (order.OrderStatuss == OrderStatus.Delivered)
                {
                    order.OrderStatuss = OrderStatus.Returning;                    
                    order.LastUpdatedTime = CoreHelper.SystemTimeNow;
                    order.LastUpdatedBy = userID;                    
                }
                else
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Bạn chỉ có thể yêu cầu trả hàng khi đơn hàng đã được giao.");
                }
            }
            else if (action == CustomerOrderAction.CancelOrder)
            {
                // Khách hàng chỉ được phép hủy đơn hàng nếu đơn hàng chưa được giao
                if (order.OrderStatuss == OrderStatus.Pending)
                {
                    order.OrderStatuss = OrderStatus.Cancelled;
                    order.LastUpdatedTime = CoreHelper.SystemTimeNow;
                    order.LastUpdatedBy = userID;

                    // Cập nhật tồn kho (hủy đơn hàng)
                    foreach (var orderDetail in order.OrderDetailss.Where(od => od.DeletedTime == null))
                    {
                        var product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(orderDetail.ProductID)
                            ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Sản phẩm với ID {orderDetail.ProductID} không tồn tại.");

                        product.QuantityInStock += orderDetail.Quantity;
                        await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
                    }
                }
                else
                {
                    throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Bạn chỉ có thể hủy đơn hàng trước khi đơn hàng được giao.");
                }
            }
            else
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Hành động không hợp lệ.");
            }

            // Cập nhật đơn hàng trong database
            await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
            await _unitOfWork.SaveAsync();

            // Gửi email thông báo thay đổi trạng thái đơn hàng
            await SendingOrderStatus_Mail(order.Id);
        }
        //public async Task UpdateAsync(string id, OrderModelView ord, OrderStatus orderStatus, PaymentStatus paymentStatus, PaymentMethod paymentMethod)
        //{
        //    string userID = GetCurrentUserId();
        //    // Lấy đối tượng hiện tại từ cơ sở dữ liệu
        //    Order orderss = await _unitOfWork.GetRepository<Order>().Entities
        //        .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
        //        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đơn hàng có ID {id} hoặc đã bị xóa."); 

        //    // Sử dụng AutoMapper để ánh xạ những thay đổi
        //    _mapper.Map(ord, orderss);  // Chỉ ánh xạ những thuộc tính có giá trị khác biệt

        //    // Cập nhật trạng thái đơn hàng
        //    orderss.OrderStatuss = orderStatus;
        //    orderss.PaymentStatuss = paymentStatus;
        //    orderss.PaymentMethod = paymentMethod;

        //    // Cập nhật thời gian cập nhật
        //    orderss.LastUpdatedTime = CoreHelper.SystemTimeNow;
        //    orderss.LastUpdatedBy = userID;

        //    // Lưu thay đổi vào cơ sở dữ liệu
        //    await _unitOfWork.GetRepository<Order>().UpdateAsync(orderss);
        //    await _unitOfWork.SaveAsync();                

        //}
        //public async Task UpdateUserPoint(string id)
        //{
        //    if(string.IsNullOrWhiteSpace(id))
        //    {
        //        throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order ID cannot be null");
        //    }
        //    Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(id)?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");
        //    ApplicationUser? user = await _userManager.FindByIdAsync(order.UserId.ToString())?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "User not found");
        //    if(!order.IsPointAdded)
        //    {
        //        await _userService.AccumulatePoints(user.Id.ToString(), order.TotalAmount, order.OrderStatuss);
        //        if(order.OrderStatuss == OrderStatus.Refunded)
        //        {
        //            order.PointsAdded = 0;
        //        }
        //        else
        //        {
        //            order.PointsAdded = (int)(order.TotalAmount / 10000) * 10;
        //        }                
        //        order.IsPointAdded = true;
        //        await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
        //        await _unitOfWork.SaveAsync();
        //    }            
        //}
        //Cập nhật TotalAmount
        //public async Task UpdateToTalAmount(string id)
        //{
        //    Order ord = await _unitOfWork.GetRepository<Order>().Entities                
        //        .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
        //        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Order with ID {id} not found or has already been deleted.");

        //    double totalDiscount = 0;
        //    double discountedTotal = ord.TotalAmount;

        //    // Lấy danh sách các voucher đã áp dụng
        //    if (ord.VoucherCode is not null && ord.VoucherCode.Count > 0)
        //    {
        //        foreach (var voucher in ord.VoucherCode)
        //        {
        //            Voucher? vch = await _unitOfWork.GetRepository<Voucher>().Entities
        //                .FirstOrDefaultAsync(v => v.VoucherCode == voucher && !v.DeletedTime.HasValue);

        //            if (vch is
        //                {
        //                    ExpiryDate: DateTime expiryDate,
        //                    LimitSalePrice: int limitSalePrice,
        //                    SalePercent: int salePercent,
        //                    UsedCount: int usedCount,
        //                    UsingLimit: int usingLimit
        //                })
        //            {
        //                // Tính toán giảm giá nếu voucher hợp lệ
        //                double discountAmount = (discountedTotal * salePercent) / 100.0;
        //                discountedTotal -= discountAmount;
        //                totalDiscount += discountAmount;
        //            }
        //        }
        //    }
        //    // Cập nhật tổng số tiền sau khi giảm giá
        //    ord.DiscountedAmount = ord.TotalAmount - totalDiscount;

        //    // Cập nhật lại thông tin đơn hàng trong cơ sở dữ liệu
        //    await _unitOfWork.GetRepository<Order>().UpdateAsync(ord);
        //    await _unitOfWork.SaveAsync();
        //}

        public async Task DeleteAsync(string id)
        {
            Order orderss = await _unitOfWork.GetRepository<Order>().Entities
                .FirstOrDefaultAsync(or => or.Id == id && !or.DeletedTime.HasValue)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đơn hàng {id} ");

            // Kiểm tra xem Order này có bất kỳ OrderDetails nào liên kết không
            bool hasOrderDetails = await _unitOfWork.GetRepository<OrderDetails>().Entities
                .AnyAsync(od => od.OrderID == id);

            if (hasOrderDetails)
            {
                // Trả về thông báo lỗi nếu tồn tại OrderDetails
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Không tìm thấy chi tiết đơn hàng");
            }

            orderss.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<Order>().UpdateAsync(orderss);
            await _unitOfWork.SaveAsync();                        
        }


        public async Task SendingPaymentStatus_Mail(string id)
        {
            if(string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Vui lòng nhập mã đơn hàng");
            }
            Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(id);
            if (order == null || order.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy đơn hàng");
            }
            ApplicationUser? user = await _userManager.FindByIdAsync(order.UserId.ToString());
            if (user == null)
            {
                   throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy user");
            }

            if (order.PaymentMethod == PaymentMethod.Online && order.PaymentStatuss == PaymentStatus.Paid && order.OrderStatuss == OrderStatus.Confirmed)
            {
                await _emailService.SendEmailAsync(user.Email, "Đơn hàng " + order.Id + " đã thanh toán thành công. Đơn hàng chưa bao gồm phí ship", "Thời gian giao hàng dự kiến " + order.estimatedDeliveryDate + ". Quý khách vui lòng thanh toán phí ship khi nhận hàng. Cảm ơn quý khách đã mua hàng tại MilkStore");                        
            }
            if (order.PaymentMethod == PaymentMethod.COD && order.PaymentStatuss == PaymentStatus.Unpaid)
            {
                if(order.OrderStatuss == OrderStatus.Confirmed)
                {
                    await _emailService.SendEmailAsync(user.Email, "Đơn hàng " + order.Id + " đã được xác nhận. Đơn hàng chưa bao gồm phí ship", "Thời gian giao hàng dự kiến " + order.estimatedDeliveryDate + ". Quý khách vui lòng thanh toán số tiền: " + order.TotalAmount + "VNĐ và phí ship khi nhận hàng. Cảm ơn quý khách đã mua hàng tại MilkStore!");
                }
            }
                          
        }
        public async Task SendingOrderStatus_Mail(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Vui lòng nhập mã đơn hàng");
            }
            Order? order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(id);
            if (order == null || order.DeletedTime != null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy đơn hàng");
            }
            ApplicationUser? user = await _userManager.FindByIdAsync(order.UserId.ToString());
            if (user == null)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Không tìm thấy người dùng");
            }
            if (order.OrderStatuss != OrderStatus.Pending)
            {
                string subject = "Đơn hàng của quý khách: " + order.User.UserName + " vừa được cập nhật";
                string message = "Trạng thái đơn hàng: " + order.Id + " đã được thay đổi thành: " + order.OrderStatuss + ". Cảm ơn quý khách đã mua hàng tại MilkStore.";

                await _emailService.SendEmailAsync(user.Email, subject, message);                
            }               
        }


        //public async Task UpdateInventoryQuantity(string orderId)
        //{
        //    if (string.IsNullOrWhiteSpace(orderId))
        //    {
        //        throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Order ID cannot be null");
        //    }
            
        //    Order order = await _unitOfWork.GetRepository<Order>().Entities
        //        .Include(or => or.OrderDetailss)
        //        .FirstOrDefaultAsync(o => o.Id == orderId && !o.DeletedTime.HasValue)
        //        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order not found");
        //    List<OrderDetails> orderDetailsList = order.OrderDetailss.Where(od => od.DeletedTime == null).ToList()                                 
        //        ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, "Order details not found");

        //    foreach (var orderDetail in orderDetailsList)
        //    {
        //        Products product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(orderDetail.ProductID)
        //            ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy sản phẩm có id {orderDetail.ProductID}");
        //        if (order.OrderStatuss == OrderStatus.Confirmed && !order.IsInventoryUpdated)
        //        {
        //            if (product.QuantityInStock >= orderDetail.Quantity)
        //            {
        //                product.QuantityInStock -= orderDetail.Quantity; // Deduct quantity                        
        //                await _unitOfWork.GetRepository<Products>().UpdateAsync(product);

        //                order.IsInventoryUpdated = true;
        //                await _unitOfWork.GetRepository<Order>().UpdateAsync(order);

        //                await _unitOfWork.SaveAsync();
        //            }
        //            else
        //            {
        //                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Not enough stock for product {product.ProductName}");
        //            }
        //        }
        //        if(order.OrderStatuss == OrderStatus.Refunded && order.IsInventoryUpdated)
        //        {
        //            product.QuantityInStock += orderDetail.Quantity; // Add quantity
        //            await _unitOfWork.GetRepository<Products>().UpdateAsync(product);
        //            await _unitOfWork.SaveAsync();
        //        }
        //    }     
        //}
    }
}
