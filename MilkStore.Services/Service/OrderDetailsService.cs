using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.Repositories.Context;
using MilkStore.ModelViews;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MilkStore.Core.Utils;
using MilkStore.Contract.Services.Interface;
using MilkStore.ModelViews.OrderModelViews;
using AutoMapper;
using MilkStore.ModelViews.ResponseDTO;

namespace MilkStore.Services.Service
{
    public class OrderDetailsService : IOrderDetailsService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IOrderService _orderService;
        private readonly DatabaseContext _context;
        private readonly IMapper _mapper;


        public OrderDetailsService(IUnitOfWork unitOfWork, DatabaseContext context, IOrderService orderService, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _context = context;
            _orderService = orderService;
            _mapper = mapper;
        }

        private OrderDetailResponseDTO MapToOrderDetailResponseDTO(OrderDetails details)
        {
            return _mapper.Map<OrderDetailResponseDTO>(details);
        }

        // Create OrderDetails
        public async Task<OrderDetails> CreateOrderDetails(OrderDetailsModelView model)
        {
            try
            {
                // Truy cập trực tiếp vào DbContext để tìm sản phẩm
                Products product = await _context.Products.FirstOrDefaultAsync(p => p.Id == model.ProductID);
                if (product == null)
                {
                    throw new Exception("Product not found");
                }

                // Map từ model sang OrderDetails
                OrderDetails orderDetails = _mapper.Map<OrderDetails>(model, opts =>
                {
                    opts.AfterMap((src, dest) =>
                    {
                        dest.UnitPrice = product.Price; // Cập nhật UnitPrice từ Product
                    });
                });

                // Chèn OrderDetails trực tiếp bằng DbContext
                _context.OrderDetails.Add(orderDetails);
                await _context.SaveChangesAsync();

                // Cập nhật tổng giá trị đơn hàng
                await _orderService.UpdateToTalAmount(orderDetails.OrderID);
                return orderDetails;
            }
            catch (Exception ex)
            {
                string innerExceptionMessage = ex.InnerException?.Message ?? ex.Message;
                throw new Exception($"An error occurred: {innerExceptionMessage}");
            }
        }

        //Read OrderDetails
        public async Task<IEnumerable<OrderDetails>> ReadOrderDetails(string? id, int page, int pageSize)
        {
            if (id == null)
            {
                IQueryable<OrderDetails> query = _unitOfWork.GetRepository<OrderDetails>().Entities
                    .Where(detail => detail.DeletedTime == null)
                    .OrderBy(detail => detail.OrderID);

                var paginated = await _unitOfWork.GetRepository<OrderDetails>()
                    .GetPagging(query, page, pageSize);

                return paginated.Items;
            }
            else
            {
                OrderDetails? od = await _unitOfWork.GetRepository<OrderDetails>()
                    .Entities
                    .FirstOrDefaultAsync(or => or.Id == id && or.DeletedTime == null);
                if (od == null)
                {
                    return Enumerable.Empty<OrderDetails>();
                }
                return new List<OrderDetails> { od };
            }
        }

        // Update OrderDetails
        public async Task<OrderDetails> UpdateOrderDetails(string id, OrderDetailsModelView model)
        {
            OrderDetails? orderDetails = await _unitOfWork.GetRepository<OrderDetails>().GetByIdAsync(id);
            if (orderDetails == null)
            {
                throw new KeyNotFoundException($"Order Details with ID: {id} was not found.");
            }

            string productID = orderDetails.ProductID;
            Products? product = await _unitOfWork.GetRepository<Products>().GetByIdAsync(productID);
            if (product == null)
            {
                throw new KeyNotFoundException($"Product with ID: {productID} was not found.");
            }

            // Cập nhật số lượng sản phẩm từ model
            orderDetails.Quantity = model.Quantity;

            // Cập nhật giá sản phẩm (UnitPrice) từ thông tin sản phẩm
            orderDetails.UnitPrice = product.Price;

            await _unitOfWork.GetRepository<OrderDetails>().UpdateAsync(orderDetails);
            await _unitOfWork.SaveAsync();

            await _orderService.UpdateToTalAmount(orderDetails.OrderID);
            return orderDetails;
        }

        // Delete OrderDetails by OrderID and ProductID
        public async Task DeleteOrderDetails(string id)
        {
            OrderDetails? od = await _unitOfWork.GetRepository<OrderDetails>().GetByIdAsync(id);
            if (od == null)
            {
                throw new KeyNotFoundException($"Order Details with ID: {id} was not found.");
            }
            od.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<OrderDetails>().UpdateAsync(od);
            await _unitOfWork.SaveAsync();
            await _orderService.UpdateToTalAmount(od.OrderID);
        }
    }
}
