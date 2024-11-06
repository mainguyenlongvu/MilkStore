using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.Repositories.Context;
using MilkStore.Core.Utils;
using MilkStore.Contract.Services.Interface;
using AutoMapper;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.Core.Base;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.Core.Constants;
using PreOrderStatus = MilkStore.ModelViews.PreOrdersModelView.PreOrderStatus;
using MilkStore.Core;

namespace MilkStore.Services.Service
{
    public class OrderDetailsService : IOrderDetailsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IOrderService _orderService;
        private readonly IMapper _mapper;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IPreOrdersService _preOrdersService;

        public OrderDetailsService(IUnitOfWork unitOfWork, IOrderService orderService, IMapper mapper, IHttpContextAccessor httpContextAccessor, IPreOrdersService preOrdersService)
        {
            _unitOfWork = unitOfWork;
            _orderService = orderService;
            _mapper = mapper;
            _httpContextAccessor = httpContextAccessor;
            _preOrdersService = preOrdersService;
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
        private async Task<Products> GetProductByIdAsync(string productId)
        {
            return await _unitOfWork.GetRepository<Products>().Entities
                .FirstOrDefaultAsync(p => p.Id == productId)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Không tìm thấy sản phẩm!");
        }

        public async Task<OrderDetails> CreateOrderDetails(OrderDetailsModelView model)
        {
            string userID = GetCurrentUserId();
            // Kiểm tra xem số lượng có hợp lệ không
            if (model.Quantity <= 0 || model.Quantity % 1 != 0)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Số lượng phải lớn hơn 0 và là số nguyên.");
            }

            // Truy cập trực tiếp để tìm sản phẩm
            Products product = await GetProductByIdAsync(model.ProductID);
            //PreOrder
            if (product.QuantityInStock < model.Quantity)
            {
                //PreOrdersModelView preOrdersModelView = new PreOrdersModelView
                //{
                //    ProductID = model.ProductID,
                //    Quantity = model.Quantity,
                //    Status = PreOrderStatus.Pending,
                //    UserID = userID
                //};
                //await _preOrdersService.CreatePreOrders(preOrdersModelView);
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Sản phẩm {product.ProductName} không đủ số lượng, vui lòng đặt trước!");
            }
            // Kiểm tra xem OrderDetails đã tồn tại hay chưa dựa trên OrderID và ProductID
            OrderDetails? existingOrderDetail = await _unitOfWork.GetRepository<OrderDetails>().Entities
                .FirstOrDefaultAsync(od => od.CreatedBy == userID && od.ProductID == model.ProductID && od.DeletedTime == null && od.Status == OrderDetailStatus.InCart);

            if (existingOrderDetail != null)
            {
                // Nếu đã tồn tại, cập nhật số lượng và tính lại tổng tiền
                existingOrderDetail.Quantity += model.Quantity;
                existingOrderDetail.UnitPrice = product.Price;
            }
            else
            {
                // Nếu chưa tồn tại, tạo OrderDetails mới
                OrderDetails orderDetails = _mapper.Map<OrderDetails>(model);
                orderDetails.UnitPrice = product.Price;
                orderDetails.CreatedBy = userID;
                orderDetails.Status = OrderDetailStatus.InCart;
                orderDetails.CreatedTime = CoreHelper.SystemTimeNow;

                // Thêm mới OrderDetails
                await _unitOfWork.GetRepository<OrderDetails>().InsertAsync(orderDetails);
                existingOrderDetail = orderDetails;
            }
            await _unitOfWork.SaveAsync();

            return existingOrderDetail;


        }


        public async Task<BasePaginatedList<OrderDetailResponseDTO>> ReadPersonalOrderDetails(string? orderId, OrderDetailStatus? orderDetailStatus, int pageIndex, int pageSize)
        {
            string userID = GetCurrentUserId();
            return await ReadAllOrderDetails(orderId, userID, orderDetailStatus, pageIndex, pageSize);
        }

        public async Task<BasePaginatedList<OrderDetailResponseDTO>> ReadAllOrderDetails(string? orderId, string? userID, OrderDetailStatus? orderDetailStatus, int pageIndex, int pageSize)
        {
            // Lọc dữ liệu cơ bản: không có DeletedTime
            IQueryable<OrderDetails>? query = _unitOfWork.GetRepository<OrderDetails>().Entities.AsNoTracking()
                .Where(od => od.DeletedTime == null);

            // Lọc theo OrderId nếu có
            if (!string.IsNullOrWhiteSpace(orderId))
            {
                query = query.Where(od => od.OrderID == orderId);
            }

            // Lọc theo UserID nếu có
            if (!string.IsNullOrWhiteSpace(userID))
            {
                query = query.Where(od => od.CreatedBy == userID);
            }

            // Lọc theo OrderDetailStatus nếu có
            if (orderDetailStatus.HasValue)
            {
                query = query.Where(od => od.Status == orderDetailStatus);
            }

            // Thực hiện phân trang với query hiện tại
            BasePaginatedList<OrderDetails>? paginatedOrderDetails = await _unitOfWork.GetRepository<OrderDetails>().GetPagging(query, pageIndex, pageSize);

            // Ánh xạ sang OrderDetailResponseDTO
            List<OrderDetailResponseDTO> odDtosResult = _mapper.Map<List<OrderDetailResponseDTO>>(paginatedOrderDetails.Items);
            return new BasePaginatedList<OrderDetailResponseDTO>(
                odDtosResult,
                paginatedOrderDetails.TotalItems,
                paginatedOrderDetails.CurrentPage,
                paginatedOrderDetails.PageSize
            );
        }

        // Update OrderDetails
        public async Task<OrderDetails> UpdateOrderDetails(string id, OrderDetailsModelView model)
        {
            // Kiểm tra số lượng từ model
            if (model.Quantity <= 0 || model.Quantity % 1 != 0)
            {
                throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, "Số lượng phải lớn hơn 0 và là một số nguyên.");
            }

            //OrderDetails orderDetails = await _unitOfWork.GetRepository<OrderDetails>().GetAllAsync()
            //    .ContinueWith(task => task.Result.FirstOrDefault(od => od.OrderID == orderId && od.ProductID == productId));
            OrderDetails? orderDetails = await _unitOfWork.GetRepository<OrderDetails>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Không tìm thấy Chi tiết đơn hàng có ID: {id} !");

            string productID = orderDetails.ProductID;
            Products product = await GetProductByIdAsync(model.ProductID);
            orderDetails.Quantity = model.Quantity;
            orderDetails.UnitPrice = product.Price;

            await _unitOfWork.GetRepository<OrderDetails>().UpdateAsync(orderDetails);
            // Cập nhật tổng tiền cho đơn hàng
            //await UpdateOrderTotal(orderDetails.OrderID);

            await _unitOfWork.SaveAsync();
            return orderDetails;
        }

        // Delete OrderDetails by OrderID and ProductID
        public async Task DeleteOrderDetails(string id)
        {
            //OrderDetails od = await _unitOfWork.GetRepository<OrderDetails>().GetAllAsync()
            //    .ContinueWith(task => task.Result.FirstOrDefault(od => od.OrderID == orderId && od.ProductID == productId));
            OrderDetails od = await _unitOfWork.GetRepository<OrderDetails>().GetByIdAsync(id)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.BadRequest, ErrorCode.BadRequest, $"Không tìm thấy Chi tiết đơn hàng có ID: {id} !");

            od.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<OrderDetails>().UpdateAsync(od);
            //await UpdateOrderTotal(od.OrderID);
            await _unitOfWork.SaveAsync();
        }
        private async Task UpdateOrderTotal(string orderId)
        {
            var order = await _unitOfWork.GetRepository<Order>().GetByIdAsync(orderId)
                ?? throw new BaseException.ErrorException(Core.Constants.StatusCodes.NotFound, ErrorCode.NotFound, $"Không tìm thấy đơn hàng.");

            // Tính tổng tiền mới
            var orderDetails = await _unitOfWork.GetRepository<OrderDetails>().Entities
                .Where(od => od.OrderID == orderId && od.DeletedTime == null)
                .ToListAsync();

            order.TotalAmount = orderDetails.Sum(od => od.Quantity * od.UnitPrice);

            // Cập nhật đơn hàng với tổng tiền mới
            await _unitOfWork.GetRepository<Order>().UpdateAsync(order);
        }
    }
}
